/**
 * order_book_good.hpp
 *
 * OPTIMISED order book leveraging AMD Turin (Zen 5) features:
 *
 *   [Cache align]  All hot structs are 64-byte aligned.
 *   [No false share] Counters are padded to separate cache lines.
 *   [Array-based]  Fixed price level array vs std::map tree.
 *   [Lock-free]    Seqlock for read-mostly best-bid/ask.
 *   [NUMA-aware]   Allocation on NUMA node local to processing thread.
 *   [Huge pages]   2 MB pages for the price level array.
 *   [Prefetch]     Next level prefetched during iteration.
 *   [Hints]        [[likely]] on common non-empty book paths.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <numa.h>
#include <sys/mman.h>

static constexpr size_t CACHE_LINE    = 64;
static constexpr int    MAX_LEVELS    = 4096;   // power of 2
static constexpr int    MAX_ORDERS    = 65536;

// -----------------------------------------------------------------------
// Order record — 64-byte aligned, fits exactly in one cache line
// -----------------------------------------------------------------------
struct alignas(CACHE_LINE) Order {
    int64_t  order_id;
    int32_t  symbol_id;
    int64_t  price_ticks;    // price as integer ticks to avoid FP
    int64_t  quantity;
    int64_t  filled_qty;
    int32_t  side;           // 0=BID, 1=ASK
    int32_t  status;
    // 8 bytes padding to reach 64
    char     _pad[8];
};
static_assert(sizeof(Order) == CACHE_LINE, "Order must be one cache line");

// -----------------------------------------------------------------------
// Price level — fits in two cache lines
// -----------------------------------------------------------------------
struct alignas(CACHE_LINE) PriceLevel {
    int64_t  price_ticks;
    int64_t  total_qty;
    int32_t  order_count;
    int32_t  head_idx;       // index into order pool
    char     _pad[CACHE_LINE - 24];
};

// -----------------------------------------------------------------------
// Book stats — each counter isolated to its own cache line
// -----------------------------------------------------------------------
struct alignas(CACHE_LINE) BookStats {
    std::atomic<uint64_t> inserts{0};
    char _pad0[CACHE_LINE - sizeof(std::atomic<uint64_t>)];

    std::atomic<uint64_t> cancels{0};
    char _pad1[CACHE_LINE - sizeof(std::atomic<uint64_t>)];

    std::atomic<uint64_t> fills{0};
    char _pad2[CACHE_LINE - sizeof(std::atomic<uint64_t>)];
};

// -----------------------------------------------------------------------
// AMD Turin optimised order book
// -----------------------------------------------------------------------
class OrderBook {
public:
    explicit OrderBook(int numa_node) : numa_node_(numa_node) {
        // Allocate price level arrays on the local NUMA node with huge pages
        size_t levels_sz = MAX_LEVELS * sizeof(PriceLevel) * 2;  // bids + asks

        bids_ = static_cast<PriceLevel*>(
            mmap(nullptr, levels_sz,
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB,
                 -1, 0));

        if (bids_ == MAP_FAILED) {
            // Fallback: regular allocation with THP
            bids_ = static_cast<PriceLevel*>(
                numa_alloc_onnode(levels_sz, numa_node_));
            madvise(bids_, levels_sz, MADV_HUGEPAGE);
        }

        asks_ = bids_ + MAX_LEVELS;
        memset(bids_, 0, levels_sz);

        // Order pool: pre-allocated on same NUMA node
        orders_ = static_cast<Order*>(
            numa_alloc_onnode(MAX_ORDERS * sizeof(Order), numa_node_));
        madvise(orders_, MAX_ORDERS * sizeof(Order), MADV_HUGEPAGE);
    }

    ~OrderBook() {
        if (bids_) munmap(bids_, MAX_LEVELS * sizeof(PriceLevel) * 2);
        if (orders_) numa_free(orders_, MAX_ORDERS * sizeof(Order));
    }

    /**
     * add_order — lock-free path using seqlock for best price update.
     * Amortised O(1): direct array index from price tick.
     */
    void add_order(const Order& o) noexcept {
        // Allocate from pool (bump pointer — no heap lock)
        uint32_t slot = order_pool_top_.fetch_add(1, std::memory_order_relaxed)
                        & (MAX_ORDERS - 1);
        orders_[slot] = o;

        // Index directly into price level array (price mapped to index)
        int idx = price_to_idx(o.price_ticks, o.side);
        PriceLevel& lvl = (o.side == 0) ? bids_[idx] : asks_[idx];

        // Update level without lock (single-writer per side per price assumed)
        lvl.price_ticks  = o.price_ticks;
        lvl.total_qty   += o.quantity;
        lvl.order_count += 1;

        // Update seqlock for best-price readers
        uint64_t seq = seq_.load(std::memory_order_relaxed);
        seq_.store(seq + 1, std::memory_order_release);  // mark dirty
        update_best(o.side);
        seq_.store(seq + 2, std::memory_order_release);  // mark clean

        stats_.inserts.fetch_add(1, std::memory_order_relaxed);
    }

    /**
     * best_bid — seqlock read: wait for stable snapshot, no lock.
     */
    int64_t best_bid_price() const noexcept {
        while (true) [[likely]] {
            uint64_t s1 = seq_.load(std::memory_order_acquire);
            if (s1 & 1) [[unlikely]] {
                _mm_pause();   // writer in progress — spin with PAUSE
                continue;
            }
            int64_t price = best_bid_ticks_.load(std::memory_order_relaxed);
            uint64_t s2   = seq_.load(std::memory_order_acquire);
            if (s1 == s2) [[likely]] return price;
        }
    }

    /**
     * total_bid_qty — iterate price levels with software prefetch.
     * Processes array linearly — hardware prefetcher handles it well,
     * but explicit prefetch ensures L1 residency for tight loops.
     */
    int64_t total_bid_qty() const noexcept {
        int64_t total = 0;
        for (int i = 0; i < MAX_LEVELS; ++i) [[likely]] {
            // Prefetch 8 cache lines ahead
            __builtin_prefetch(&bids_[i + 8], 0, 1);
            if (bids_[i].order_count > 0) [[likely]] {
                total += bids_[i].total_qty;
            }
        }
        return total;
    }

    BookStats stats_;

private:
    PriceLevel*              bids_    = nullptr;
    PriceLevel*              asks_    = nullptr;
    Order*                   orders_  = nullptr;
    int                      numa_node_;

    alignas(CACHE_LINE) std::atomic<uint64_t> seq_{0};
    char _pad_seq[CACHE_LINE - sizeof(std::atomic<uint64_t>)];

    alignas(CACHE_LINE) std::atomic<int64_t> best_bid_ticks_{0};
    char _pad_bid[CACHE_LINE - sizeof(std::atomic<int64_t>)];

    alignas(CACHE_LINE) std::atomic<int64_t> best_ask_ticks_{INT64_MAX};
    char _pad_ask[CACHE_LINE - sizeof(std::atomic<int64_t>)];

    alignas(CACHE_LINE) std::atomic<uint32_t> order_pool_top_{0};

    static int price_to_idx(int64_t price_ticks, int side) noexcept {
        // Map price to array index using modular hashing
        return static_cast<int>(price_ticks & (MAX_LEVELS - 1));
    }

    void update_best(int side) noexcept {
        if (side == 0) {  // BID
            int64_t best = 0;
            for (int i = MAX_LEVELS - 1; i >= 0; --i) {
                if (bids_[i].order_count > 0) [[unlikely]] {
                    best = bids_[i].price_ticks;
                    break;
                }
            }
            best_bid_ticks_.store(best, std::memory_order_relaxed);
        } else {
            int64_t best = INT64_MAX;
            for (int i = 0; i < MAX_LEVELS; ++i) {
                if (asks_[i].order_count > 0) [[unlikely]] {
                    best = asks_[i].price_ticks;
                    break;
                }
            }
            best_ask_ticks_.store(best, std::memory_order_relaxed);
        }
    }
};
