#pragma once

#include <cstddef>
#include <cstdint>

// Long-lived H3 stability helpers (Http3Upstream + unit tests).
// Free of libevent so host-side tests link without full client deps.
//
// HTTP/2 already does the correct multi-stream split (see net/src/http2.cpp +
// Http2Upstream::consume):
//   - connection-level FC is released as soon as body is accepted
//   - stream-level FC is released only when LAN has accepted the bytes
//     (CLIENT_EVENT_DATA_SENT → ServerUpstream::consume)
//
// HTTP/3 must mirror that. nghttp3 delivers DATA once (must copy or use in
// callback). Http3Client::consume_stream() extends *both* connection and stream
// windows; consume_connection() extends connection only. Stream-only credit is
// approximated by consume_stream() plus a connection-surplus counter so multi-
// stream traffic is not wedged behind one slow CONNECT (the failure mode that
// required process restart).
//
// === Download path / BDP (OpenWrt field + quic-go / ngtcp2 docs) ===
// Throughput ≤ window / RTT. At ~55 ms RTT and ~300 Mbit target:
//   BDP ≈ 300e6/8 * 0.055 ≈ 2.1 MiB — stream RX must be multi-MB and grow.
// Server (quiche) defaults: initial stream 1 MiB, max_stream_window 16 MiB —
// so server RX auto-tunes → client UPLOAD ~70 Mbit worked in the field.
// Client had max_stream_window == initial (1 MiB) → auto-tune cannot grow →
// DOWNLOAD stuck ~8–30 Mbit while H2 multi hit ~180–280. Fix: initial stream
// large enough for first RTTs, max_stream_window >> initial (match server 16 MiB).
// Connection initial capped for OpenWrt RAM (~242 MiB); max > initial enables
// conn-level auto-tune. Soft unread hints track max windows (log only).
//
// RSS product goal for long-lived OpenWrt (musl): **stable plateau** after bulk
// (no climb/wedge), not matching post-restart cold RSS. musl does not return
// small-heap pages to the OS; process restart is the only full baseline reset.

// Initial stream RX (advertised in TP) — enough for ~150+ Mbit @ 55 ms without waiting for tune.
static constexpr uint64_t QUIC_STREAM_WINDOW_SIZE = 4ul * 1024 * 1024;
// Auto-tune ceiling (ngtcp2 max_stream_window). MUST be > initial or growth is a no-op.
// Matches tt-server QuicSettings::default_max_stream_window (16 MiB).
static constexpr uint64_t QUIC_STREAM_MAX_WINDOW_SIZE = 16ul * 1024 * 1024;

// Initial connection RX — multi-stream budget without 100 MiB OpenWrt RSS balloon.
static constexpr uint64_t QUIC_CONNECTION_WINDOW_SIZE = 24ul * 1024 * 1024;
// Auto-tune ceiling for connection window (must be > initial).
static constexpr uint64_t QUIC_CONNECTION_MAX_WINDOW_SIZE = 48ul * 1024 * 1024;

static constexpr uint64_t QUIC_MAX_STREAMS_NUM = 4ul * 1024;

// Soft app-unread hints for tests / logging only (never drop on_body data).
static constexpr size_t H3_MAX_UNREAD_PER_CONN = size_t(QUIC_STREAM_MAX_WINDOW_SIZE);
static constexpr size_t H3_MAX_UNREAD_GLOBAL = size_t(QUIC_CONNECTION_MAX_WINDOW_SIZE);

/** True if pushing `add` would exceed `cap`. */
static inline bool h3_unread_would_exceed_cap(size_t have, size_t add, size_t cap) {
    return have >= cap || add > (cap - have);
}

static inline bool h3_global_unread_would_exceed(size_t total_have, size_t add, size_t global_cap) {
    return h3_unread_would_exceed_cap(total_have, add, global_cap);
}

/**
 * How many connection-window bytes to extend for `received` newly accepted body
 * bytes, given `surplus` connection credit already applied via combined
 * stream+connection extends (consume_stream). Updates `surplus`.
 */
static inline size_t h3_conn_credit_to_extend(size_t received, size_t &surplus) {
    if (received == 0) {
        return 0;
    }
    if (surplus >= received) {
        surplus -= received;
        return 0;
    }
    const size_t n = received - surplus;
    surplus = 0;
    return n;
}

/** Record that consume_stream(n) also extended the connection window by n. */
static inline void h3_note_combined_stream_conn_credit(size_t n, size_t &surplus) {
    surplus += n;
}

/** True when stream auto-tune can grow past the initial TP (required for high-BDP DL). */
static inline bool h3_stream_autotune_enabled() {
    return QUIC_STREAM_MAX_WINDOW_SIZE > QUIC_STREAM_WINDOW_SIZE;
}

/** True when connection auto-tune can grow past the initial TP. */
static inline bool h3_connection_autotune_enabled() {
    return QUIC_CONNECTION_MAX_WINDOW_SIZE > QUIC_CONNECTION_WINDOW_SIZE;
}
