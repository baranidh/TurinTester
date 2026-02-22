/**
 * fix_parser_bad.hpp
 *
 * Intentionally UNOPTIMISED FIX message parser.
 * Demonstrates patterns that the Turin Latency Analyzer WILL flag.
 *
 * Issues planted (sorted by severity):
 *   [CRITICAL] Byte-by-byte scalar scan — no AVX-512
 *   [CRITICAL] std::mutex on parsing hot path
 *   [CRITICAL] Dynamic allocation (new) per message
 *   [MAJOR]    Structs without cache-line alignment
 *   [MAJOR]    No NUMA-aware allocation
 *   [MAJOR]    No huge pages for message buffer
 *   [MINOR]    No branch prediction hints
 *   [MINOR]    No prefetch in field lookup loop
 */

#pragma once

#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// --------------------------------------------------------------------
// BAD: struct has no alignas(64) — will straddle cache lines
// --------------------------------------------------------------------
struct FixField {
    int   tag;
    char* value;
    int   length;
};

// BAD: no padding between thread-shared counters — false sharing
struct ParseStats {
    long messages_parsed;
    long fields_parsed;
    long errors;
    long bytes_processed;
};

// --------------------------------------------------------------------
// BAD: Parser class uses mutex + dynamic allocation per message
// --------------------------------------------------------------------
class FixParser {
public:
    FixParser() {
        // BAD: std::vector without reserve — will reallocate
        fields_.push_back(FixField{0, nullptr, 0});
    }

    // BAD: mutex on hot parsing path
    std::mutex parse_mutex_;

    // Returns dynamically allocated vector — heap alloc per call
    std::vector<FixField>* parse(const char* buf, int len) {
        std::unique_lock<std::mutex> lock(parse_mutex_);   // BAD: mutex

        // BAD: heap allocation per message
        std::vector<FixField>* result = new std::vector<FixField>();

        // BAD: scalar byte-by-byte scan — no AVX-512
        int i = 0;
        while (i < len) {
            // find '=' delimiter
            int tag_start = i;
            while (i < len && buf[i] != '=') {
                i++;  // scalar scan — should be _mm512_cmpeq_epi8
            }
            int tag_len = i - tag_start;
            i++; // skip '='

            // find SOH delimiter (0x01)
            int val_start = i;
            while (i < len && buf[i] != '\x01') {
                i++;  // another scalar scan
            }

            // BAD: std::string allocation per field
            std::string tag_str(buf + tag_start, tag_len);
            int tag = std::stoi(tag_str);

            FixField f;
            f.tag    = tag;
            f.value  = const_cast<char*>(buf + val_start);
            f.length = i - val_start;
            result->push_back(f);  // BAD: may reallocate

            i++; // skip SOH
        }

        stats_.messages_parsed++;
        return result;  // BAD: caller must delete
    }

    // BAD: no [[likely]]/[[unlikely]] on common branches
    bool validate_checksum(const char* buf, int len) {
        unsigned int sum = 0;
        for (int i = 0; i < len - 7; i++) {
            sum += (unsigned char)buf[i];  // scalar loop — no SIMD
        }
        sum = sum % 256;
        // no branch prediction hint:
        if (sum != extract_checksum(buf, len)) {
            return false;
        }
        return true;
    }

    ParseStats stats_;

private:
    std::vector<FixField> fields_;  // BAD: no capacity reserve

    unsigned int extract_checksum(const char* buf, int len) {
        // BAD: no prefetch, no SIMD
        for (int i = len - 7; i < len; i++) {
            if (buf[i] == '=') {
                return std::stoi(std::string(buf + i + 1, 3));
            }
        }
        return 0;
    }
};
