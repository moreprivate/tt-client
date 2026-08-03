#pragma once

#include <cstddef>
#include <cstdint>

// Long-lived H3 stability helpers (Http3Upstream + unit tests).
// Free of libevent so host-side tests link without full client deps.
//
// Stability = reclaim (consume-after-buffer, free-on-empty, MemoryBuffer chunk drop),
// not "cap for its own sake". Connection window is below the old 100 MiB pin that
// let max_window alone sticky-hold ~RSS until process restart; stream window stays
// multi-stream capable. Unread cap is fail-closed safety against unbounded app hold.

static constexpr uint64_t QUIC_CONNECTION_WINDOW_SIZE = 32ul * 1024 * 1024;
static constexpr uint64_t QUIC_STREAM_WINDOW_SIZE = 1ul * 1024 * 1024;
static constexpr uint64_t QUIC_MAX_STREAMS_NUM = 4ul * 1024;
static constexpr size_t H3_MAX_UNREAD_PER_CONN = 1024ul * 1024;

/** True if pushing `add` bytes onto an unread buffer of size `have` would exceed `cap`. */
static inline bool h3_unread_would_exceed_cap(size_t have, size_t add, size_t cap) {
    return have >= cap || add > (cap - have);
}
