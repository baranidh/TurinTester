/**
 * risk_engine_bad.cpp
 *
 * Intentionally UNOPTIMISED pre-trade risk engine.
 * Demonstrates all the patterns the Turin Latency Analyzer flags.
 *
 * Anti-patterns:
 *   [CRITICAL] Dynamic allocation in check_order() hot path
 *   [CRITICAL] std::mutex on risk table
 *   [CRITICAL] condition_variable for order signalling
 *   [CRITICAL] No thread affinity — threads may migrate across CCDs
 *   [MAJOR]    No NUMA-aware memory for risk tables
 *   [MAJOR]    No huge pages for position arrays
 *   [MAJOR]    Structs without cache-line alignment
 *   [MINOR]    No branch hints on common pass/reject paths
 *   [MINOR]    memory_order_seq_cst on hot atomic counter
 */

#include "fix_parser_bad.hpp"
#include "order_book_bad.hpp"

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// BAD: no alignas(64) — RiskLimit struct spans cache lines
struct RiskLimit {
    long   max_notional;
    long   max_position;
    long   max_order_qty;
    double max_price;
    int    symbol_id;
    bool   enabled;
};

// BAD: no padding — symbol_limits array elements will share cache lines
//      when accessed by threads on different cores
struct PositionRecord {
    int  symbol_id;
    long net_position;
    long gross_bought;
    long gross_sold;
    long open_orders;
};

// BAD: Global mutex protecting the entire risk table
std::mutex g_risk_mutex;

// BAD: unordered_map causes dynamic allocation on lookup expansion
std::unordered_map<int, RiskLimit>      g_risk_limits;
std::unordered_map<int, PositionRecord> g_positions;

// BAD: condition_variable for order event notification — OS kernel involved
std::condition_variable g_order_cv;
std::mutex              g_order_mutex;
std::vector<Order*>     g_pending_orders;

// BAD: counter without memory_order hint — defaults to seq_cst → MFENCE
std::atomic<long> g_orders_checked{0};
std::atomic<long> g_orders_rejected{0};

// --------------------------------------------------------------------
// Hot path — called for EVERY order, must be <1 μs on AMD Turin
// --------------------------------------------------------------------
bool check_order(const Order& o) {
    // BAD: mutex on entire risk table for every order check
    std::lock_guard<std::mutex> lk(g_risk_mutex);

    // BAD: unordered_map lookup — potential hash table resize / bucket scan
    auto lit = g_risk_limits.find(o.symbol_id);
    if (lit == g_risk_limits.end()) {
        return false;  // no hint: this is the unlikely path
    }
    const RiskLimit& limit = lit->second;

    if (!limit.enabled) {
        return false;
    }

    // BAD: position lookup — another hash table miss
    auto pit = g_positions.find(o.symbol_id);
    if (pit == g_positions.end()) {
        return false;
    }
    PositionRecord& pos = pit->second;

    // Risk checks — scalar comparisons, no SIMD across multiple limits
    long notional = static_cast<long>(o.price * o.quantity);
    if (notional > limit.max_notional) {
        g_orders_rejected++;  // BAD: seq_cst store + MFENCE
        return false;
    }
    if (o.quantity > limit.max_order_qty) {
        g_orders_rejected++;
        return false;
    }
    long new_position = pos.net_position + (o.side == 'B' ? o.quantity : -o.quantity);
    if (new_position > limit.max_position || new_position < -limit.max_position) {
        g_orders_rejected++;
        return false;
    }

    g_orders_checked++;  // BAD: seq_cst
    return true;
}

// --------------------------------------------------------------------
// Order processing thread — no CPU affinity set
// --------------------------------------------------------------------
void order_processing_thread() {
    // BAD: thread created without CPU affinity — may migrate between CCDs
    while (true) {
        std::unique_lock<std::mutex> lk(g_order_mutex);
        // BAD: condition_variable — blocks in kernel, wakeup latency >1 μs
        g_order_cv.wait(lk, [] { return !g_pending_orders.empty(); });

        Order* o = g_pending_orders.back();
        g_pending_orders.pop_back();
        lk.unlock();

        if (check_order(*o)) {
            // convert to native binary protocol — not shown
        }

        delete o;  // BAD: heap free in hot path
    }
}

// --------------------------------------------------------------------
// Main — no NUMA setup, no huge pages, no CPU isolation
// --------------------------------------------------------------------
int main() {
    // BAD: allocating risk tables on default NUMA node
    // No: numa_alloc_onnode(), no: madvise(MADV_HUGEPAGE)

    // BAD: threads created with no affinity
    std::thread worker1(order_processing_thread);
    std::thread worker2(order_processing_thread);

    // Simulate some work
    FixParser parser;
    const char* fix_msg =
        "8=FIX.4.2\x01"
        "35=D\x01"
        "49=CLIENT\x01"
        "56=EXCHANGE\x01"
        "11=ORDER001\x01"
        "55=AAPL\x01"
        "54=1\x01"
        "38=100\x01"
        "44=150.50\x01"
        "10=123\x01";

    auto* fields = parser.parse(fix_msg, strlen(fix_msg));
    delete fields;  // BAD: caller manages heap memory

    worker1.join();
    worker2.join();
    return 0;
}
