#pragma once

#include <cstddef>
#include <cstdint>

// Long-lived OpenWrt/H3 stability bounds (used by Http3Upstream + unit tests).
// Kept free of libevent so host-side tests can link without full client deps.

// Connection window was 100 MiB; ngtcp2 can grow recv buffers to max_window.
static constexpr uint64_t QUIC_CONNECTION_WINDOW_SIZE = 12ul * 1024 * 1024;
static constexpr uint64_t QUIC_STREAM_WINDOW_SIZE = 256ul * 1024;
static constexpr uint64_t QUIC_MAX_STREAMS_NUM = 4ul * 1024;
static constexpr size_t H3_MAX_UNREAD_PER_CONN = 384ul * 1024;

/** True if pushing `add` bytes onto an unread buffer of size `have` would exceed `cap`. */
static inline bool h3_unread_would_exceed_cap(size_t have, size_t add, size_t cap) {
    return have >= cap || add > (cap - have);
}
