#include <algorithm>

#include "common/socket_address.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"
#include "vpn_fsm.h"
#include "vpn_manager.h"

using namespace ag::vpn_fsm;

namespace ag {

static bool is_fatal_error(const void *ctx, void *data);
static bool need_to_ping_on_recovery(const void *ctx, void *data);
static bool fall_into_recovery(const void *ctx, void *data);
static bool no_connect_attempts(const void *ctx, void *data);
static bool network_lost(const void *ctx, void *data);
static bool connected_once(const void *ctx, void *data);

static void run_ping(void *ctx, void *data);
static void connect_client(void *ctx, void *data);
static void complete_connect(void *ctx, void *data);
static void fail_connect_with_no_attempts(void *ctx, void *data);
static void retry_connect(void *ctx, void *data);
static void prepare_for_recovery(void *ctx, void *data);
static void prepare_for_recovery_nc(void *ctx, void *data);
static void reconnect_client(void *ctx, void *data);
static void finalize_recovery(void *ctx, void *data);
static void do_disconnect(void *ctx, void *data);
static void start_listening(void *ctx, void *data);
static void on_wrong_connect_state(void *ctx, void *data);
static void on_wrong_listen_state(void *ctx, void *data);

static void raise_state(void *ctx, void *data);

static bool can_complete(const void *ctx, void *data);
static bool is_kill_switch_on(const void *ctx, void *data);
static bool should_postpone(const void *ctx, void *data);

static void complete_request(void *ctx, void *data);
static void postpone_request(void *ctx, void *data);
static void reject_request(void *ctx, void *data);
static void bypass_until_connected(void *ctx, void *data);

// clang-format off
static constexpr FsmTransitionEntry TRANSITION_TABLE[] = {
        {VPN_SS_DISCONNECTED,     CE_DO_CONNECT,          Fsm::ANYWAY,              run_ping,               VPN_SS_CONNECTING,       raise_state},
        {VPN_SS_DISCONNECTED,     CE_CLIENT_DISCONNECTED, Fsm::ANYWAY,              Fsm::DO_NOTHING,        Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_DISCONNECTED,     CE_SHUTDOWN,            Fsm::ANYWAY,              do_disconnect,          Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_DISCONNECTED,     CE_START_LISTENING,     Fsm::ANYWAY,              on_wrong_listen_state,  Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_DISCONNECTED,     CE_NETWORK_CHANGE,      Fsm::ANYWAY,              Fsm::DO_NOTHING,        Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},

        {VPN_SS_CONNECTING,       CE_RETRY_CONNECT,       Fsm::ANYWAY,              run_ping,               Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_PING_READY,          Fsm::ANYWAY,              connect_client,         Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           is_fatal_error,           complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           fall_into_recovery,       prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           no_connect_attempts,      complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           Fsm::OTHERWISE,           retry_connect,          Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_CLIENT_READY,        Fsm::ANYWAY,              complete_connect,       VPN_SS_CONNECTED,        raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, is_fatal_error,           complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, fall_into_recovery,       prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, no_connect_attempts,      complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, Fsm::OTHERWISE,           retry_connect,          Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_ABANDON_ENDPOINT,    is_fatal_error,           complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_ABANDON_ENDPOINT,    Fsm::OTHERWISE,           retry_connect,          Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_NETWORK_CHANGE,      no_connect_attempts,      fail_connect_with_no_attempts, VPN_SS_DISCONNECTED, raise_state},
        {VPN_SS_CONNECTING,       CE_NETWORK_CHANGE,      network_lost,             do_disconnect,          VPN_SS_WAITING_FOR_NETWORK, raise_state},
        // OpenWrt: tun0 ifup fires VPN_NS_CONNECTED while still CONNECTING. That must NOT
        // abort into recovery (was: fall_into_recovery → WAITING_RECOVERY with error=0).
        // Keep connecting; only network *loss* is actionable here.
        {VPN_SS_CONNECTING,       CE_NETWORK_CHANGE,      Fsm::OTHERWISE,           Fsm::DO_NOTHING,        Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},

        {VPN_SS_CONNECTED,        CE_NETWORK_CHANGE,      network_lost,             do_disconnect,           VPN_SS_WAITING_FOR_NETWORK, raise_state},
        {VPN_SS_CONNECTED,        CE_NETWORK_CHANGE,      Fsm::OTHERWISE,           prepare_for_recovery_nc, VPN_SS_WAITING_RECOVERY,    raise_state},
        {VPN_SS_CONNECTED,        CE_ABANDON_ENDPOINT,    is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTED,        CE_ABANDON_ENDPOINT,    Fsm::OTHERWISE,           prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},

        {VPN_SS_WAITING_RECOVERY, CE_NETWORK_CHANGE,      network_lost,             do_disconnect,          VPN_SS_WAITING_FOR_NETWORK, raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_NETWORK_CHANGE,      Fsm::OTHERWISE,           run_ping,               VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_DO_RECOVERY,         need_to_ping_on_recovery, run_ping,               VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_DO_RECOVERY,         Fsm::OTHERWISE,           connect_client,         VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_CLIENT_DISCONNECTED, is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_CLIENT_DISCONNECTED, Fsm::OTHERWISE,           Fsm::DO_NOTHING,        Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_WAITING_RECOVERY, CE_ABANDON_ENDPOINT,    is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},

        // While recovering, CONNECTED re-notifications (tun0/SQM/firewall) must not restart recovery.
        {VPN_SS_RECOVERING,       CE_NETWORK_CHANGE,      network_lost,             do_disconnect,           VPN_SS_WAITING_FOR_NETWORK, raise_state},
        {VPN_SS_RECOVERING,       CE_NETWORK_CHANGE,      Fsm::OTHERWISE,           Fsm::DO_NOTHING,         Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_RECOVERING,       CE_PING_READY,          Fsm::ANYWAY,              reconnect_client,       Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_RECOVERING,       CE_PING_FAIL,           is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_RECOVERING,       CE_PING_FAIL,           Fsm::OTHERWISE,           prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},
        {VPN_SS_RECOVERING,       CE_CLIENT_READY,        Fsm::ANYWAY,              finalize_recovery,      VPN_SS_CONNECTED,        raise_state},
        {VPN_SS_RECOVERING,       CE_ABANDON_ENDPOINT,    is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_RECOVERING,       CE_ABANDON_ENDPOINT,    Fsm::OTHERWISE,           prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},

        {VPN_SS_WAITING_FOR_NETWORK, CE_NETWORK_CHANGE,   network_lost,             Fsm::DO_NOTHING,               Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_WAITING_FOR_NETWORK, CE_NETWORK_CHANGE,   connected_once,           prepare_for_recovery_nc,       VPN_SS_WAITING_RECOVERY, raise_state},
        {VPN_SS_WAITING_FOR_NETWORK, CE_NETWORK_CHANGE,   no_connect_attempts,      fail_connect_with_no_attempts, VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_WAITING_FOR_NETWORK, CE_NETWORK_CHANGE,   Fsm::OTHERWISE,           retry_connect,                 VPN_SS_CONNECTING,       raise_state},

        {Fsm::ANY_SOURCE_STATE,   CE_CLIENT_DISCONNECTED, is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {Fsm::ANY_SOURCE_STATE,   CE_CLIENT_DISCONNECTED, Fsm::OTHERWISE,           prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},
        {Fsm::ANY_SOURCE_STATE,   CE_SHUTDOWN,            Fsm::ANYWAY,              do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {Fsm::ANY_SOURCE_STATE,   CE_DO_CONNECT,          Fsm::ANYWAY,              on_wrong_connect_state, VPN_SS_DISCONNECTED,     raise_state},
        {Fsm::ANY_SOURCE_STATE,   CE_START_LISTENING,     Fsm::ANYWAY,              start_listening,        Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},

        {Fsm::ANY_SOURCE_STATE,   CE_COMPLETE_REQUEST,    can_complete,             complete_request,       Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {Fsm::ANY_SOURCE_STATE,   CE_COMPLETE_REQUEST,    should_postpone,          postpone_request,       Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {Fsm::ANY_SOURCE_STATE,   CE_COMPLETE_REQUEST,    is_kill_switch_on,        reject_request,         Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {Fsm::ANY_SOURCE_STATE,   CE_COMPLETE_REQUEST,    Fsm::OTHERWISE,           bypass_until_connected, Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
};
// clang-format on

FsmTransitionTable vpn_fsm::get_transition_table() {
    return {std::begin(TRANSITION_TABLE), std::end(TRANSITION_TABLE)};
}

static void postponement_window_timer_cb(evutil_socket_t, short, void *arg);

static void initiate_recovery(Vpn *vpn) {
    if (vpn->recovery.attempts >= vpn->upstream_config->recovery.attempts) {
        log_vpn(vpn, warn, "Maximum recovery attempts ({}) exhausted — disconnecting",
                vpn->upstream_config->recovery.attempts);
        vpn->submit([vpn] {
            log_vpn(vpn, warn, "Disconnecting: recovery failed after max attempts");
            vpn->recovery = {};
            vpn->pending_error = {VPN_EC_LOCATION_UNAVAILABLE, "Maximum number of recovery attempts has been made"};
            vpn->fsm.perform_transition(CE_SHUTDOWN, nullptr);
        });
        return;
    }

    auto now = SteadyClock::now();
    Millis elapsed{};
    if (vpn->recovery.time.start_ts != SteadyClock::time_point{}) {
        elapsed = std::max(duration_cast<Millis>(now - vpn->recovery.time.attempt_start_ts), Millis{});
    } else {
        vpn->recovery.time.start_ts = now;
        vpn->postponement_window_timer.reset(
                evtimer_new(vpn_event_loop_get_base(vpn->ev_loop.get()), postponement_window_timer_cb, vpn));
        timeval tv = ms_to_timeval(VPN_DEFAULT_POSTPONEMENT_WINDOW_MS);
        evtimer_add(vpn->postponement_window_timer.get(), &tv);
    }

    // try to recover immediately if a previous attempt has taken the whole period
    Millis time_to_next{};
    if (vpn->recovery.time.between_attempts >= elapsed) {
        time_to_next = vpn->recovery.time.between_attempts - elapsed;
    }

    // Anti-thrash: after a recent recovery fire (e.g. path flap + fail-fast QUIC death),
    // do not start another 0ms reconnect immediately even though between_attempts reset.
    if (vpn->last_recovery_fire_ts != SteadyClock::time_point{}) {
        const Millis since_fire =
                std::max(duration_cast<Millis>(now - vpn->last_recovery_fire_ts), Millis{});
        const Millis min_gap{VPN_MIN_RECOVERY_FIRE_GAP_MS};
        if (since_fire < min_gap) {
            time_to_next = std::max(time_to_next, min_gap - since_fire);
        }
    }

    ++vpn->recovery.attempts;
    // After first schedule, ensure subsequent gaps use at least 1s * backoff (initial may be 0).
    if (vpn->recovery.time.between_attempts.count() == 0 && vpn->recovery.attempts == 1) {
        // Keep time_to_next as computed (0 or min-gap); seed next gap after scheduling.
    }
    log_vpn(vpn, info, "Schedule recovery attempt {}/{} in {}ms (backoff next window)", vpn->recovery.attempts,
            vpn->upstream_config->recovery.attempts, time_to_next.count());
    vpn->recovery.task = event_loop::schedule(
            vpn->ev_loop.get(),
            [vpn]() {
                log_vpn(vpn, info, "Recovering session (attempt starting)...");
                vpn->recovery.task.release();
                vpn->last_recovery_fire_ts = SteadyClock::now();
                vpn->recovery.time.attempt_start_ts = vpn->last_recovery_fire_ts;
                vpn->fsm.perform_transition(vpn_fsm::CE_DO_RECOVERY, nullptr);
            },
            time_to_next);

    // Seed/backoff: if initial was 0, next wait becomes 1000ms then * rate.
    if (vpn->recovery.time.between_attempts.count() == 0) {
        vpn->recovery.time.between_attempts = Millis{1000};
    } else {
        vpn->recovery.time.between_attempts = std::chrono::round<Millis>(
                vpn->recovery.time.between_attempts * vpn->upstream_config->recovery.backoff_rate);
    }
    auto next_attempt_ts = now + time_to_next;
    if (next_attempt_ts - vpn->recovery.time.start_ts
            >= Millis{vpn->upstream_config->recovery.location_update_period_ms}) {
        log_vpn(vpn, info, "Resetting recovery timing (location re-ping period elapsed)");
        vpn->recovery.time = {};
    }

    vpn->recovery.time.to_next = time_to_next;
}

static void pinger_handler(void *arg, const LocationsPingerResult *result) {
    if (result == nullptr) {
        // ignore ping finished event
        return;
    }

    auto *vpn = (Vpn *) arg;
    assert(!vpn->selected_endpoint.has_value());
    vpn->selected_endpoint.reset();
    vpn->client.tcp_socket.reset();
    vpn->client.quic_connector.reset();
    bool failure_induces_location_unavailable = std::exchange(vpn->ping_failure_induces_location_unavailable, false);
    if (result->ping_ms < 0) {
        VpnError error = failure_induces_location_unavailable
                ? VpnError{VPN_EC_LOCATION_UNAVAILABLE, "None of the endpoints were pinged successfully"}
                : VpnError{VPN_EC_ERROR, "Failed to ping location"};
        log_vpn(vpn, warn, "{}", error.text);
        vpn->fsm.perform_transition(vpn_fsm::CE_PING_FAIL, &error);
        return;
    }

    VpnEndpoint *endpoints_end =
            vpn->upstream_config->location.endpoints.data + vpn->upstream_config->location.endpoints.size;
    if (std::none_of(vpn->upstream_config->location.endpoints.data, endpoints_end,
                [seek = result->endpoint](const VpnEndpoint &iter) {
                    return vpn_endpoint_equals(seek, &iter);
                })) {
        vpn->ping_failure_induces_location_unavailable = failure_induces_location_unavailable;
        VpnError error = {VPN_EC_ERROR, "Best available endpoint wasn't found in location"};
        log_vpn(vpn, warn, "{}: {}", error.text, *result->endpoint);
        vpn->fsm.perform_transition(vpn_fsm::CE_PING_FAIL, &error);
        return;
    }

    vpn->selected_endpoint.emplace(vpn_endpoint_clone(result->endpoint),
            result->relay ? std::make_optional(vpn_relay_clone(result->relay)) : std::nullopt);
    log_vpn(vpn, info, "Using endpoint: {}, relay={}, ping={}ms", *vpn->selected_endpoint->endpoint,
            vpn->selected_endpoint->relay.has_value()
                    ? SocketAddress(vpn->selected_endpoint->relay->get()->address).str()
                    : "none",
            result->ping_ms);

    if (result->is_quic) {
        vpn->client.quic_connector.reset((QuicConnectorResult *) result->conn_state);
    } else {
        vpn->client.tcp_socket.reset((TcpSocket *) result->conn_state);
    }

    vpn->client.update_bypass_ip_availability();

    vpn->fsm.perform_transition(vpn_fsm::CE_PING_READY, nullptr);
}

static bool is_fatal_error_code(int code) {
    return code == VPN_EC_AUTH_REQUIRED || code == VPN_EC_LOCATION_UNAVAILABLE
            || code == VPN_EC_CERTIFICATE_VERIFICATION_FAILED;
}

static void run_client_connect(Vpn *vpn, std::optional<Millis> timeout = std::nullopt) {
    VpnError error = vpn->client.connect(vpn->make_client_upstream_config(), timeout);
    if (error.code == VPN_EC_NOERROR) {
        vpn->client_state = vpn_manager::CLIS_CONNECTING;
        vpn->pending_error.reset();
    } else {
        log_vpn(vpn, dbg, "Failed to connect: {} ({})", safe_to_string_view(error.text), error.code);
        vpn->pending_error = error;
        vpn->submit([vpn] {
            vpn->fsm.perform_transition(CE_CLIENT_DISCONNECTED, nullptr);
        });
    }
}

static bool need_to_ping_on_recovery(const void *ctx, void *) {
    const Vpn *vpn = (Vpn *) ctx;
    if (!vpn->selected_endpoint.has_value()) {
        // we lost endpoint for some reason, need to refresh the location
        return true;
    }
    if (vpn->network_changed_before_recovery) {
        return true;
    }

    auto now = SteadyClock::now();
    return now - vpn->recovery.time.start_ts >= Millis{vpn->upstream_config->recovery.location_update_period_ms};
}

static bool fall_into_recovery(const void *ctx, void *) {
    const auto *vpn = (Vpn *) ctx;
    return std::holds_alternative<vpn_manager::ConnectFallIntoRecovery>(vpn->connect_retry_info);
}

static bool no_connect_attempts(const void *ctx, void *) {
    const auto *vpn = (Vpn *) ctx;
    const auto *several_attempts = std::get_if<vpn_manager::ConnectSeveralAttempts>(&vpn->connect_retry_info);
    return several_attempts != nullptr && several_attempts->attempts_left == 0;
}

static bool network_lost(const void *, void *data) {
    auto state = *(VpnNetworkState *) data;
    return state == VPN_NS_NOT_CONNECTED;
}

static bool connected_once(const void *ctx, void *) {
    const auto *vpn = (Vpn *) ctx;
    return vpn->connected_once;
}

static bool is_fatal_error(const void *ctx, void *data) {
    const VpnError *error = (VpnError *) data;
    const Vpn *vpn = (Vpn *) ctx;
    return (error != nullptr && is_fatal_error_code(error->code))
            || is_fatal_error_code(vpn->pending_error.value_or(VpnError{}).code);
}

static void run_ping(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->stop_pinging();

    uint32_t quic_max_idle_timeout =
            2 * (vpn->upstream_config->timeout_ms + vpn->upstream_config->health_check_timeout_ms);

    LocationsPingerInfo pinger_info = {
            .timeout_ms = vpn->upstream_config->location_ping_timeout_ms,
            .locations = {&vpn->upstream_config->location, 1},
            .rounds = 1,
            .main_protocol = vpn->upstream_config->main_protocol,
            .anti_dpi = vpn->upstream_config->anti_dpi,
            // HTTP/2 location probes do not complete endpoint cert verification, so
            // TCP sockets are never handed off. Only a half-open QUIC connection may
            // be handed off; cert verify is armed on the upstream before the first
            // saved server datagram is processed. For AUTO/HTTP2-win, open a fresh
            // verified TLS/HTTP2 session instead of reusing the probe.
            .handoff = vpn->upstream_config->main_protocol != VPN_UP_HTTP2,
            .quic_max_idle_timeout_ms = quic_max_idle_timeout,
            .quic_version = 0,
    };

    // Speed up recovery if we have already connected through a relay by pinging through the relay in parallel.
    if (vpn->selected_endpoint.has_value() && vpn->selected_endpoint->relay.has_value()
            && vpn->recovery.time.start_ts != SteadyClock::time_point{}) {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        pinger_info.relay_parallel = vpn->selected_endpoint->relay->get();
    }

    vpn->pinger.reset(locations_pinger_start(
            &pinger_info, {pinger_handler, vpn}, vpn->ev_loop.get(), vpn->network_manager.get()));

    vpn->pending_error.reset();
    vpn->selected_endpoint.reset();

    // We might have gotten here through CE_NETWORK_CHANGE with a pending recovery task. Cancel it.
    if (vpn->recovery.task.has_value()) {
        vpn->recovery.task.reset();
        vpn->recovery.time.attempt_start_ts = SteadyClock::now();
    }

    log_vpn(vpn, trace, "Done");
}

static void connect_client(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    run_client_connect(vpn);

    log_vpn(vpn, trace, "Done");
}

static void complete_connect(void *ctx, void *data) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    const VpnError *error = (VpnError *) data;
    if (!vpn->pending_error.has_value() && error != nullptr && error->code != VPN_EC_NOERROR) {
        vpn->disconnect();
        vpn->pending_error = *error;
    }
    if (vpn->pending_error.has_value() && !is_fatal_error(ctx, data) && no_connect_attempts(ctx, nullptr)) {
        vpn->pending_error = {VPN_EC_INITIAL_CONNECT_FAILED, "Number of connection attempts exceeded"};
    }

    vpn->recovery = {};

    if (!vpn->pending_error.has_value()) {
        vpn->client.do_health_check();
    }

    log_vpn(vpn, trace, "Done");
}

void fail_connect_with_no_attempts(void *ctx, void *) {
    VpnError error = {VPN_EC_INITIAL_CONNECT_FAILED, "Number of connection attempts exceeded"};
    complete_connect(ctx, &error);
}

static void retry_connect(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    if (auto *several_attempts = std::get_if<vpn_manager::ConnectSeveralAttempts>(&vpn->connect_retry_info)) {
        several_attempts->attempts_left -= 1;
    } else {
        assert(0);
    }

    vpn->disconnect();

    vpn->submit([vpn] {
        vpn->fsm.perform_transition(CE_RETRY_CONNECT, nullptr);
    });

    log_vpn(vpn, trace, "Done");
}

static void prepare_for_recovery(void *ctx, void *data) {
    Vpn *vpn = (Vpn *) ctx;
    const VpnError *error = (VpnError *) data;
    if (!vpn->pending_error.has_value() && error != nullptr && error->code != VPN_EC_NOERROR) {
        vpn->pending_error = *error;
    }
    log_vpn(vpn, info, "Entering recovery: reason={} ({}) fsm_state={}",
            safe_to_string_view(vpn->pending_error.value_or(VpnError{}).text),
            vpn->pending_error.value_or(VpnError{}).code,
            magic_enum::enum_name((VpnSessionState) vpn->fsm.get_state()));

    vpn->disconnect();
    initiate_recovery(vpn);
}

void prepare_for_recovery_nc(void *ctx, void *) {
    // `prepare_for_recovery` expects `VpnError *` as parameters, we have `VpnNetworkState *`.
    prepare_for_recovery(ctx, nullptr);
}

static void reconnect_client(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->disconnect_client();

    run_client_connect(vpn, std::min(vpn->recovery.time.between_attempts, Millis{vpn->upstream_config->timeout_ms}));

    log_vpn(vpn, trace, "Done");
}

static void finalize_recovery(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->client.update_bypass_ip_availability();
    vpn->recovery = {};
    vpn->stop_pinging();
    vpn->postponement_window_timer.reset();
    vpn->complete_postponed_requests();
    vpn->reset_bypassed_connections();

    log_vpn(vpn, trace, "Done");
}

static void do_disconnect(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->recovery = {};
    vpn->disconnect();

    log_vpn(vpn, trace, "Done");
}

static void start_listening(void *ctx, void *data) {
    auto *vpn = (Vpn *) ctx;
    auto *args = (StartListeningArgs *) data;

    log_vpn(vpn, info, "...");
    VpnError error = vpn->client.listen(std::move(args->listener), args->config);
    if (error.code != VPN_EC_NOERROR) {
        log_vpn(vpn, err, "Client run failed: {} ({})", safe_to_string_view(error.text), error.code);
        vpn->submit([vpn, error] {
            vpn->pending_error = error;
            vpn->fsm.perform_transition(CE_SHUTDOWN, nullptr);
        });
    } else {
        log_vpn(vpn, info, "Client has been successfully prepared to run");
    }
}

static void on_wrong_connect_state(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;

    vpn->disconnect();

    vpn->pending_error = {VPN_EC_INVALID_STATE, "Invalid state for connecting"};
    log_vpn(vpn, err, "{}: {}", vpn->pending_error->text,
            magic_enum::enum_name((VpnSessionState) vpn->fsm.get_state()));
}

static void on_wrong_listen_state(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, err, "Invalid state for listenning: {}",
            magic_enum::enum_name((VpnSessionState) vpn->fsm.get_state()));
}

static void raise_state(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    auto state = (VpnSessionState) vpn->fsm.get_state();
    VpnStateChangedEvent event = {vpn->upstream_config->location.id, state};
    std::string kex_group_name;

    switch (state) {
    case VPN_SS_WAITING_RECOVERY:
        event.waiting_recovery_info = {
                .error = std::exchange(vpn->pending_error, std::nullopt).value_or(VpnError{}),
                .time_to_next_ms = uint32_t(vpn->recovery.time.to_next.count()),
        };
        log_vpn(vpn, info, "{}: reason={} ({}) next_attempt_ms={}", magic_enum::enum_name(state),
                safe_to_string_view(event.waiting_recovery_info.error.text),
                event.waiting_recovery_info.error.code, event.waiting_recovery_info.time_to_next_ms);
        break;
    case VPN_SS_CONNECTED: {
        vpn->connected_once = true;
        int kex_group_nid = vpn->client.endpoint_upstream->kex_group_nid();
        kex_group_name = kex_group_name_by_nid(kex_group_nid);
        event.connected_info = {
                // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
                .endpoint = vpn->selected_endpoint->endpoint.get(),
                // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
                .relay = vpn->selected_endpoint->relay.has_value() ? vpn->selected_endpoint->relay->get() : nullptr,
                .protocol = vpn->client.endpoint_upstream->get_protocol(),
                .kex_group = kex_group_name.c_str(),
        };
        log_vpn(vpn, info, "{}: protocol={} kex={}", magic_enum::enum_name(state),
                magic_enum::enum_name(event.connected_info.protocol), kex_group_name);
        break;
    }
    case VPN_SS_DISCONNECTED:
    case VPN_SS_CONNECTING:
    case VPN_SS_RECOVERING:
        vpn->network_changed_before_recovery = false;
        [[fallthrough]];
    case VPN_SS_WAITING_FOR_NETWORK:
        event.error = std::exchange(vpn->pending_error, std::nullopt).value_or(VpnError{});
        if (event.error.code != VPN_EC_NOERROR) {
            log_vpn(vpn, info, "{}: error={} ({})", magic_enum::enum_name(state),
                    safe_to_string_view(event.error.text), event.error.code);
        } else {
            log_vpn(vpn, info, "{}", magic_enum::enum_name(state));
        }
        break;
    }

    vpn->handler.func(vpn->handler.arg, VPN_EVENT_STATE_CHANGED, (void *) &event);
}

static bool can_complete(const void *ctx, void *data) {
    auto *result = (ConnectRequestResult *) data;
    if (result->action == VPN_CA_FORCE_BYPASS) {
        return true;
    }
    const auto *vpn = (Vpn *) ctx;
    auto state = VpnSessionState(vpn->fsm.get_state());
    return state == VPN_SS_CONNECTED || state == VPN_SS_CONNECTING || state == VPN_SS_DISCONNECTED
            || state == VPN_SS_WAITING_FOR_NETWORK || vpn->client.tunnel->should_complete_immediately(result->id);
}

static bool is_kill_switch_on(const void *ctx, void *) {
    const auto *vpn = (Vpn *) ctx;
    return vpn->client.kill_switch_on;
}

static void complete_request(void *ctx, void *data) {
    auto *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    auto *result = (ConnectRequestResult *) data;
    vpn->client.complete_connect_request(result->id, result->action);

    log_vpn(vpn, trace, "Done");
}

static void reject_request(void *ctx, void *data) {
    auto *vpn = (Vpn *) ctx;

    auto *result = (ConnectRequestResult *) data;
    log_vpn(vpn, dbg, "Rejecting connection [L:{}]: not ready to route through endpoint", result->id);
    vpn->client.reject_connect_request(result->id);

    log_vpn(vpn, trace, "Done");
}

static void bypass_until_connected(void *ctx, void *data) {
    auto *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    auto *result = (ConnectRequestResult *) data;
    vpn->bypassed_connection_ids.emplace_back(result->id);
    vpn->client.complete_connect_request(result->id, VPN_CA_FORCE_BYPASS);

    log_vpn(vpn, trace, "Done");
}

static bool should_postpone(const void *ctx, void *) {
    auto *vpn = (Vpn *) ctx;
    return vpn->postponement_window_timer != nullptr;
}

static void postpone_request(void *ctx, void *data) {
    auto *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    auto *request = (ConnectRequestResult *) data;
    vpn->postponed_requests.emplace_back(std::move(*request));

    log_vpn(vpn, trace, "Done");
}

static void postponement_window_timer_cb(evutil_socket_t, short, void *arg) {
    auto *vpn = (Vpn *) arg;
    log_vpn(vpn, trace, "...");

    vpn->postponement_window_timer.reset();
    for (auto &request : vpn->postponed_requests) {
        if (vpn->client.kill_switch_on) {
            vpn->client.reject_connect_request(request.id);
        } else {
            vpn->client.complete_connect_request(request.id, VPN_CA_FORCE_BYPASS);
            vpn->bypassed_connection_ids.emplace_back(request.id);
        }
    }
    vpn->postponed_requests.clear();

    log_vpn(vpn, trace, "Done");
}

} // namespace ag
