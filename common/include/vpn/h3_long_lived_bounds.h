#pragma once

#include <cstddef>
#include <cstdint>

// Long-lived H3 stability helpers (Http3Upstream + unit tests).
// Free of libevent so host-side tests link without full client deps.
//
// Stability = reclaim (FC via deferred consume, free-on-empty, MemoryBuffer chunk drop).
// Throughput needs full stream/connection windows; do not "fix" RSS by shrinking
// windows or closing streams at an app-side cap. Unread cap is a safety ceiling only
// if app buffering races FC; normal path is stream window as the bound.

static constexpr uint64_t QUIC_CONNECTION_WINDOW_SIZE = 100ul * 1024 * 1024;
static constexpr uint64_t QUIC_STREAM_WINDOW_SIZE = 1ul * 1024 * 1024;
static constexpr uint64_t QUIC_MAX_STREAMS_NUM = 4ul * 1024;
// Safety ceiling (>> stream window); primary bound is QUIC FC + free-on-empty reclaim.
static constexpr size_t H3_MAX_UNREAD_PER_CONN = 4ul * 1024 * 1024;

/** True if pushing `add` bytes onto an unread buffer of size `have` would exceed `cap`. */
static inline bool h3_unread_would_exceed_cap(size_t have, size_t add, size_t cap) {
    return have >= cap || add > (cap - have);
}
