/**
 * order_book_bad.hpp
 *
 * Intentionally UNOPTIMISED order book.
 * Demonstrates patterns the Turin Latency Analyzer WILL flag.
 *
 * Issues planted:
 *   [CRITICAL] std::map (tree-based) for price levels — cache unfriendly
 *   [CRITICAL] Dynamic allocation per order
 *   [CRITICAL] std::mutex on order insertion
 *   [MAJOR]    No cache-line alignment on OrderRecord
 *   [MAJOR]    No NUMA-aware allocation
 *   [MAJOR]    No huge pages for book storage
 *   [MINOR]    No prefetch in iteration
 *   [MINOR]    No branch prediction hints
 */

#pragma once

#include <map>
#include <mutex>
#include <vector>
#include <string>

// BAD: no alignas(64) — likely spans two cache lines
struct Order {
    long long order_id;
    int       symbol_id;
    double    price;
    long      quantity;
    long      filled_qty;
    char      side;       // 'B' or 'S'
    char      status;
    short     flags;
};

// BAD: no alignas(64), no false-sharing protection between counters
struct PriceLevel {
    double     price;
    long       total_qty;
    int        order_count;
    std::vector<Order*> orders;  // BAD: pointer indirection, no NUMA locality
};

class OrderBook {
public:
    // BAD: std::map is a red-black tree — O(log N) with many cache misses
    std::map<double, PriceLevel> bids_;
    std::map<double, PriceLevel> asks_;

    std::mutex book_mutex_;  // BAD: coarse mutex on entire book

    void add_order(const Order& o) {
        std::lock_guard<std::mutex> lk(book_mutex_);  // BAD: mutex

        // BAD: dynamic allocation per order
        Order* heap_order = new Order(o);

        auto& side_map = (o.side == 'B') ? bids_ : asks_;
        auto it = side_map.find(o.price);  // BAD: tree traversal, cache misses
        if (it == side_map.end()) {
            PriceLevel lvl;
            lvl.price       = o.price;
            lvl.total_qty   = o.quantity;
            lvl.order_count = 1;
            lvl.orders.push_back(heap_order);  // BAD: vector realloc possible
            side_map[o.price] = lvl;           // BAD: tree insert
        } else {
            it->second.total_qty   += o.quantity;
            it->second.order_count += 1;
            it->second.orders.push_back(heap_order);
        }
    }

    // BAD: returns a newly allocated string — heap alloc in hot path
    std::string best_bid_str() const {
        if (bids_.empty()) return "EMPTY";
        auto it = bids_.rbegin();
        return std::to_string(it->second.price);  // BAD: allocation
    }

    long best_bid_qty() const {
        if (bids_.empty()) return 0;
        // no branch prediction hint on common case (non-empty)
        return bids_.rbegin()->second.total_qty;
    }

    // BAD: iterates tree without prefetch — every node pointer dereference
    //      is a potential cache miss
    long total_bid_quantity() const {
        long total = 0;
        for (const auto& [price, level] : bids_) {
            total += level.total_qty;  // no prefetch of next node
        }
        return total;
    }
};
