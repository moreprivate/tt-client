#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cxxopts.hpp>
#include <magic_enum/magic_enum.hpp>
#include <toml++/toml.h>

#include "common/logger.h"
#include "common/net_utils.h"
#include "common/socket_address.h"
#include "net/network_manager.h"
#include "net/tls.h"
#include "utils.h"
#include "vpn/trusttunnel/auto_network_monitor.h"
#include "vpn/trusttunnel/client.h"
#include "vpn/trusttunnel/config.h"
#include "vpn/trusttunnel/version.h"

#ifdef __APPLE__
#include "AppleSleepNotifier.h"
#endif

#ifdef _WIN32
#include <filesystem>
#endif

#ifdef __linux__
#include <net/if.h>
#include <sys/resource.h>
#endif

static constexpr std::string_view DEFAULT_CONFIG_FILE = "trusttunnel_client.toml";

using namespace ag;

static const ag::Logger g_logger("TRUSTTUNNEL_CLIENT_APP");
static std::atomic_bool keep_running{true};
static std::condition_variable g_waiter;
static std::mutex g_waiter_mutex;
static std::weak_ptr<TrustTunnelClient> g_client;
// Last breadcrumb for crash dumps (async-signal-safe: fixed buffer only).
static char g_last_event[256] = "boot";
static std::atomic<uint64_t> g_event_seq{0};

static std::function<void(SocketProtectEvent *)> get_protect_socket_callback(const TrustTunnelConfig &config);
static std::function<void(VpnVerifyCertificateEvent *)> get_verify_certificate_callback();
static std::function<void(VpnStateChangedEvent *)> get_state_changed_callback();
static std::function<void(VpnConnectionInfoEvent *)> get_connection_info_callback();

#ifdef _WIN32
static int service_run(const cxxopts::ParseResult *cli_args);
static int service_uninstall();
static int service_install(const std::string &config_path);
static void report_service_status(DWORD current_state, DWORD win32_exit_code, DWORD wait_hint);
static bool g_svc_running = false;
#endif

int run_client(const cxxopts::ParseResult &cli_args);

// ---------------------------------------------------------------------------
// Diagnostics: always go to stderr (procd → logread) AND the app logger.
// ---------------------------------------------------------------------------

static void note_event(const char *fmt, ...) {
    char buf[sizeof(g_last_event)];
    va_list ap;
    va_start(ap, fmt);
    (void) vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    // Best-effort copy into global breadcrumb (racy under multi-thread; good enough).
    std::snprintf(g_last_event, sizeof(g_last_event), "#%llu %s",
            (unsigned long long) ++g_event_seq, buf);
    errlog(g_logger, "EVENT {}", g_last_event);
    // Force visibility even if logger level is wrong.
    std::fprintf(stderr, "trusttunnel_client EVENT %s\n", g_last_event);
    std::fflush(stderr);
}

static void dump_file_to_stderr(const char *path, const char *label, size_t max_bytes = 4096) {
#ifndef _WIN32
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        std::fprintf(stderr, "  %s: (open failed %s errno=%d)\n", label, path, errno);
        return;
    }
    std::fprintf(stderr, "  --- %s (%s) ---\n", label, path);
    char buf[512];
    size_t total = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        size_t take = (size_t) n;
        if (total + take > max_bytes) {
            take = max_bytes - total;
        }
        (void) write(STDERR_FILENO, buf, take);
        total += take;
        if (total >= max_bytes) {
            std::fprintf(stderr, "\n  ... truncated at %zu bytes\n", max_bytes);
            break;
        }
    }
    if (total == 0 || (total > 0 && buf[(total - 1) % sizeof(buf)] != '\n')) {
        std::fputc('\n', stderr);
    }
    close(fd);
#else
    (void) path;
    (void) label;
    (void) max_bytes;
#endif
}

static int count_fds() {
#ifndef _WIN32
    DIR *d = opendir("/proc/self/fd");
    if (!d) {
        return -1;
    }
    int n = 0;
    while (readdir(d) != nullptr) {
        ++n;
    }
    closedir(d);
    return n > 2 ? n - 2 : n; // ., ..
#else
    return -1;
#endif
}

/** Full process dump for logread. Safe from normal threads; not for signal handlers. */
static void dump_process_diagnostics(const char *why) {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
#ifndef _WIN32
    const int pid = (int) getpid();
#else
    const int pid = 0;
#endif
    std::fprintf(stderr,
            "\n========== trusttunnel_client DEATH_DUMP begin why=%s pid=%d last_event=%s wall_ms=%lld ==========\n",
            why ? why : "?", pid, g_last_event, (long long) ms);
    errlog(g_logger, "DEATH_DUMP begin why={} pid={} last_event={}", why ? why : "?", pid, g_last_event);

#ifndef _WIN32
    dump_file_to_stderr("/proc/self/status", "proc_status", 8192);
    dump_file_to_stderr("/proc/self/cmdline", "cmdline", 512);
    dump_file_to_stderr("/proc/self/comm", "comm", 64);
    dump_file_to_stderr("/proc/meminfo", "meminfo_head", 1500);
    dump_file_to_stderr("/proc/self/limits", "limits", 2048);
    dump_file_to_stderr("/proc/self/statm", "statm", 256);
    dump_file_to_stderr("/proc/self/cgroup", "cgroup", 1024);
    dump_file_to_stderr("/proc/self/oom_score", "oom_score", 64);
    dump_file_to_stderr("/proc/self/oom_score_adj", "oom_score_adj", 64);
    dump_file_to_stderr("/proc/net/dev", "net_dev", 4096);
    // TCP/UDP socket counts (full table can be huge under load).
    {
        std::ifstream tcp("/proc/net/tcp");
        std::ifstream tcp6("/proc/net/tcp6");
        std::ifstream udp("/proc/net/udp");
        auto count_lines = [](std::ifstream &f) -> int {
            int n = 0;
            std::string line;
            while (std::getline(f, line)) {
                ++n;
            }
            return n > 0 ? n - 1 : 0; // skip header
        };
        std::fprintf(stderr, "  sockets: tcp4=%d tcp6=%d udp4=%d fd_count≈%d\n", count_lines(tcp), count_lines(tcp6),
                count_lines(udp), count_fds());
    }
    {
        struct rusage ru {};
        if (getrusage(RUSAGE_SELF, &ru) == 0) {
            std::fprintf(stderr, "  rusage: maxrss_kb=%ld utime=%ld.%06ld stime=%ld.%06ld nvcsw=%ld nivcsw=%ld\n",
                    (long) ru.ru_maxrss, (long) ru.ru_utime.tv_sec, (long) ru.ru_utime.tv_usec, (long) ru.ru_stime.tv_sec,
                    (long) ru.ru_stime.tv_usec, (long) ru.ru_nvcsw, (long) ru.ru_nivcsw);
        }
    }
    // tun0 presence
    dump_file_to_stderr("/sys/class/net/tun0/operstate", "tun0_operstate", 64);
    dump_file_to_stderr("/sys/class/net/tun0/statistics/rx_bytes", "tun0_rx_bytes", 64);
    dump_file_to_stderr("/sys/class/net/tun0/statistics/tx_bytes", "tun0_tx_bytes", 64);
    dump_file_to_stderr("/proc/self/maps", "maps_head", 2048);
#endif

    std::fprintf(stderr, "========== trusttunnel_client DEATH_DUMP end why=%s ==========\n\n", why ? why : "?");
    std::fflush(stderr);
    errlog(g_logger, "DEATH_DUMP end why={}", why ? why : "?");
}

#ifndef _WIN32
/** Async-signal-safe minimal dump (only write/open/read). */
static void dump_process_diagnostics_signal_safe(int sig) {
    const char *name = "SIGNAL";
    if (sig == SIGSEGV) {
        name = "SIGSEGV";
    } else if (sig == SIGABRT) {
        name = "SIGABRT";
    } else if (sig == SIGBUS) {
        name = "SIGBUS";
    } else if (sig == SIGFPE) {
        name = "SIGFPE";
    } else if (sig == SIGILL) {
        name = "SIGILL";
    }
    const char head[] = "\n========== trusttunnel_client FATAL_SIGNAL ";
    const char mid[] = " last_event=";
    const char tail[] = " ==========\n";
    (void) write(STDERR_FILENO, head, sizeof(head) - 1);
    (void) write(STDERR_FILENO, name, strlen(name));
    (void) write(STDERR_FILENO, mid, sizeof(mid) - 1);
    (void) write(STDERR_FILENO, g_last_event, strlen(g_last_event));
    (void) write(STDERR_FILENO, tail, sizeof(tail) - 1);

    auto dump_path = [](const char *path) {
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            return;
        }
        char b[256];
        for (;;) {
            ssize_t n = read(fd, b, sizeof(b));
            if (n <= 0) {
                break;
            }
            (void) write(STDERR_FILENO, b, (size_t) n);
        }
        (void) write(STDERR_FILENO, "\n", 1);
        close(fd);
    };
    dump_path("/proc/self/status");
    dump_path("/proc/self/oom_score");
    dump_path("/proc/meminfo");
}
#endif

static void stop_trusttunnel_client(const char *why = "stop_trusttunnel_client") {
    note_event("stop_trusttunnel_client: %s", why ? why : "unspecified");
    dump_process_diagnostics(why ? why : "stop_trusttunnel_client");
    keep_running = false;
    g_waiter.notify_all();
}

static void on_atexit_dump() {
    // If we are exiting the process, always leave a dump in logread.
    dump_process_diagnostics("atexit");
}

static void sighandler(int sig) {
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    if (auto client = g_client.lock()) {
#ifndef _WIN32
        if (sig == SIGHUP) {
            note_event("SIGHUP → synthetic network flap");
            client->notify_network_change(ag::VPN_NS_NOT_CONNECTED);
            std::thread t([client]() {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                client->notify_network_change(ag::VPN_NS_CONNECTED);
            });
            t.detach();
            return;
        }
#endif
        char why[64];
        std::snprintf(why, sizeof(why), "signal_%d", sig);
        stop_trusttunnel_client(why);
    } else {
        dump_process_diagnostics("signal_no_client");
        exit(1);
    }
}

#ifndef _WIN32
static void fatal_signal_handler(int sig) {
    dump_process_diagnostics_signal_safe(sig);
    signal(sig, SIG_DFL);
    raise(sig);
}
#endif

static void setup_sighandler() {
#ifdef _WIN32
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
#else
    signal(SIGPIPE, SIG_IGN);
    signal(SIGSEGV, fatal_signal_handler);
    signal(SIGABRT, fatal_signal_handler);
    signal(SIGBUS, fatal_signal_handler);
    signal(SIGFPE, fatal_signal_handler);
    signal(SIGILL, fatal_signal_handler);
    std::atexit(on_atexit_dump);
    // Block SIGINT and SIGTERM - they will be waited using sigwait().
    sigset_t sigset; // NOLINT(cppcoreguidelines-init-variables)
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);
    std::thread([sigset] {
        int signum = 0;
        while (true) {
            sigwait(&sigset, &signum);
            sighandler(signum);
        }
    }).detach();
#endif
}

int main(int argc, char **argv) {
    setup_sighandler();

    cxxopts::Options args("trusttunnel_client", "TrustTunnel console client");
    // clang-format off
    args.add_options()
            ("v,version", "Print version")
            ("s", "Skip verify certificate", cxxopts::value<bool>()->default_value("false"))
            ("c,config", "Config file name.", cxxopts::value<std::string>()->default_value(std::string(DEFAULT_CONFIG_FILE)))
            ("l,loglevel", "Logging level. Possible values: error, warn, info, debug, trace.", cxxopts::value<std::string>()->default_value("info"))
            ("h,help", "Print usage");
#ifdef _WIN32
    args.add_options()
            ("service-install", "Install as Windows service", cxxopts::value<bool>()->default_value("false"))
            ("service-uninstall", "Uninstall Windows service", cxxopts::value<bool>()->default_value("false"));
    args.add_options("internal")
            ("service-run", "Run as Windows service", cxxopts::value<bool>()->default_value("false"));
#endif
    // clang-format on

    auto result = args.parse(argc, argv);
    if (result.count("version")) {
        std::cout << args.program() << " " TRUSTTUNNEL_VERSION << '\n';
        return 0;
    }

    if (result.count("help")) {
        // `{""}` mean print only options from default options group
        std::cout << args.help({""}) << '\n';
        return 1;
    }

#ifdef _WIN32
    if (result.count("service-install") && result.count("service-uninstall")) {
        errlog(g_logger, "--service-install and --service-uninstall are mutually exclusive");
        return 1;
    }
    if (result.count("service-install")) {
        return service_install(result["config"].as<std::string>());
    }
    if (result.count("service-uninstall")) {
        return service_uninstall();
    }
    if (result["service-run"].as<bool>()) {
        return service_run(&result);
    }
#endif

    return run_client(result);
}

int run_client(const cxxopts::ParseResult &cli_args) {
    toml::parse_result parse_result = toml::parse_file(cli_args["config"].as<std::string>());
    if (!parse_result) {
        errlog(g_logger, "Failed parsing configuration: {}", parse_result.error().description());
        return 1;
    }

    std::optional config_res = TrustTunnelConfig::build_config(parse_result.table());
    if (!config_res) {
        errlog(g_logger, "Failed to parse config");
        return 1;
    }
    auto &config = *config_res;
    if (!TrustTunnelCliUtils::apply_cmd_args(config, cli_args)) {
        return 1;
    }
    ag::Logger::set_log_level(config.loglevel);

    vpn_post_quantum_group_set_enabled(config.post_quantum_group_enabled);

    VpnCallbacks callbacks = {
            .protect_handler = get_protect_socket_callback(config),
            .verify_handler = get_verify_certificate_callback(),
            .state_changed_handler = get_state_changed_callback(),
            .connection_info_handler = get_connection_info_callback(),
    };

    std::string bound_if;
    if (const auto *tun = std::get_if<TrustTunnelConfig::TunListener>(&config.listener)) {
        bound_if = tun->bound_if;
    }

    auto client = std::make_shared<TrustTunnelClient>(std::move(config), std::move(callbacks));
    g_client = client;
    AutoNetworkMonitor network_monitor(client.get(), std::move(bound_if));
    if (!network_monitor.start()) {
        errlog(g_logger, "Failed to start network monitor");
        return 1;
    }

    auto res = client->set_system_dns();
    if (res) {
        errlog(g_logger, "{}", res->str());
        return 1;
    }
    res = client->connect(TrustTunnelClient::AutoSetup{});
    if (res) {
        errlog(g_logger, "{}", res->str());
        return 1;
    }

#ifdef _WIN32
    if (g_svc_running) {
        report_service_status(SERVICE_RUNNING, NO_ERROR, 0);
    }
#endif

#ifdef __APPLE__
    auto sleep_notifier = std::make_unique<AppleSleepNotifier>(
            [client_weak = std::weak_ptr(client)] {
                if (auto client = client_weak.lock()) {
                    client->notify_sleep();
                }
            },
            [client_weak = std::weak_ptr(client)] {
                if (auto client = client_weak.lock()) {
                    client->notify_wake();
                }
            });
#endif

    std::unique_lock<std::mutex> lock(g_waiter_mutex);
    g_waiter.wait(lock, []() {
        return !keep_running.load();
    });

#ifdef __APPLE__
    sleep_notifier.reset();
#endif

    network_monitor.stop();
    client->disconnect();

    return 0;
}

std::function<void(SocketProtectEvent *)> get_protect_socket_callback(const TrustTunnelConfig &config) {
    const auto *tun = std::get_if<TrustTunnelConfig::TunListener>(&config.listener);
    if (!tun) {
        return [](auto) {};
    }

    return [](SocketProtectEvent *event) {
#ifdef __APPLE__
        uint32_t idx = vpn_network_manager_get_outbound_interface();
        if (idx == 0) {
            if (vpn_network_manager_get_tunnel_active()) {
                event->result = -1;
            }
            return;
        }
        if (event->peer->sa_family == AF_INET) {
            if (setsockopt(event->fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx)) != 0) {
                event->result = -1;
            }
        } else if (event->peer->sa_family == AF_INET6) {
            if (setsockopt(event->fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx)) != 0) {
                event->result = -1;
            }
        }
#endif // __APPLE__

#ifdef __linux__
        uint32_t idx = vpn_network_manager_get_outbound_interface();
        if (idx == 0) {
            if (vpn_network_manager_get_tunnel_active()) {
                event->result = -1;
            }
            return;
        }
        char if_name[IF_NAMESIZE]{};
        if (!if_indextoname(idx, if_name)) {
            event->result = -1;
            return;
        }
        std::string bound_if{if_name};
        if (setsockopt(event->fd, SOL_SOCKET, SO_BINDTODEVICE, bound_if.data(), (socklen_t) bound_if.size()) != 0) {
            event->result = -1;
        }
#endif

#ifdef _WIN32
        bool protect_success = vpn_win_socket_protect(event->fd, event->peer);
        if (!protect_success) {
            event->result = -1;
        }
#endif
    };
}

static std::function<void(VpnVerifyCertificateEvent *)> get_verify_certificate_callback() {
    return [](VpnVerifyCertificateEvent *event) {
        const char *err = tls_verify_cert(event->cert, event->chain, nullptr);
        if (err == nullptr) {
            tracelog(g_logger, "Certificate verified successfully");
            event->result = 0;
        } else {
            errlog(g_logger, "Failed to verify certificate: {}", err);
            event->result = -1;
        }
    };
}

static bool is_fatal_disconnect_error(int code) {
    // Mirror core is_fatal_error_code: only these should kill the daemon process.
    return code == VPN_EC_AUTH_REQUIRED || code == VPN_EC_LOCATION_UNAVAILABLE
            || code == VPN_EC_CERTIFICATE_VERIFICATION_FAILED;
}

static std::function<void(VpnStateChangedEvent *)> get_state_changed_callback() {
    return [](VpnStateChangedEvent *event) {
        // VpnStateChangedEvent is a union: only one arm is valid per state.
        // Reading event->error on CONNECTED was garbage (connected_info overlay) → SIGSEGV
        // when formatting err_text (seen as err_code=-2082471592 err_text=(null) then crash).
        switch (event->state) {
        case VPN_SS_DISCONNECTED: {
            const int code = event->error.code;
            const char *text = event->error.text;
            note_event("VPN_STATE DISCONNECTED code=%d text=%s", code, text ? text : "");
            if (code != 0) {
                errlog(g_logger, "Error: {} {}", code, safe_to_string_view(text));
            }
            // Full dump only on disconnect (not every state — caused OpenWrt load spike).
            dump_process_diagnostics("VPN_SS_DISCONNECTED");
            if (is_fatal_disconnect_error(code)) {
                stop_trusttunnel_client("fatal_disconnect");
            } else if (auto client = g_client.lock()) {
                warnlog(g_logger,
                        "Non-fatal disconnect (code={}) — in-process reconnect (keep process/tun alive)", code);
                note_event("request_reconnect after non-fatal DISCONNECTED code=%d", code);
                client->request_reconnect();
            } else {
                stop_trusttunnel_client("disconnect_no_client");
            }
            break;
        }
        case VPN_SS_WAITING_RECOVERY: {
            const auto &wr = event->waiting_recovery_info;
            note_event("VPN_STATE WAITING_RECOVERY next_ms=%u code=%d text=%s", wr.time_to_next_ms,
                    wr.error.code, wr.error.text ? wr.error.text : "");
            infolog(g_logger, "Waiting recovery: to next={}ms error={} {}", wr.time_to_next_ms, wr.error.code,
                    safe_to_string_view(wr.error.text));
            break;
        }
        case VPN_SS_CONNECTED: {
            const auto &ci = event->connected_info;
            note_event("VPN_STATE CONNECTED protocol=%s kex=%s", magic_enum::enum_name(ci.protocol).data(),
                    ci.kex_group ? ci.kex_group : "?");
            infolog(g_logger, "Successfully connected to endpoint protocol={} kex={}",
                    magic_enum::enum_name(ci.protocol), ci.kex_group ? ci.kex_group : "?");
            break;
        }
        case VPN_SS_CONNECTING:
            note_event("VPN_STATE CONNECTING");
            break;
        case VPN_SS_RECOVERING:
            note_event("VPN_STATE RECOVERING");
            break;
        case VPN_SS_WAITING_FOR_NETWORK:
            note_event("VPN_STATE WAITING_FOR_NETWORK");
            break;
        }
    };
}

static std::function<void(VpnConnectionInfoEvent *)> get_connection_info_callback() {
    return [](VpnConnectionInfoEvent *event) {
        std::string src = SocketAddress(*event->src).host_str(/*ipv6_brackets=*/true);
        std::string proto = event->proto == IPPROTO_TCP ? "TCP" : "UDP";
        std::string dst;
        if (event->domain) {
            dst = event->domain;
        }
        if (event->dst) {
            dst = AG_FMT("{}({})", dst, src);
        }
        auto action = magic_enum::enum_name(event->action);

        std::string log_message;

        log_message = fmt::format("{}, {} -> {}. Action: {}", proto, src, dst, action);

        dbglog(g_logger, "{}", log_message);
    };
}

#ifdef _WIN32

static constexpr std::wstring_view SERVICE_NAME = L"TrustTunnelClient";
static constexpr std::wstring_view SERVICE_DISPLAY_NAME = L"TrustTunnel VPN Client";

using ScHandle = ag::UniquePtr<std::remove_pointer_t<SC_HANDLE>, &CloseServiceHandle>;

static const ag::Logger g_svc_logger("WIN_SERVICE");

static SERVICE_STATUS_HANDLE g_status_handle = nullptr;
static SERVICE_STATUS g_service_status = {};
static std::mutex g_service_status_mutex;
// g_svc_cli_args is safe to dereference in service_main() because StartServiceCtrlDispatcherW
// blocks until the service stops, and the ParseResult it points to lives in main().
static const cxxopts::ParseResult *g_svc_cli_args = nullptr;

static void report_service_status(DWORD current_state, DWORD win32_exit_code, DWORD wait_hint) {
    std::lock_guard lock(g_service_status_mutex);
    static DWORD check_point = 1;

    g_service_status.dwCurrentState = current_state;
    g_service_status.dwWin32ExitCode = win32_exit_code;
    g_service_status.dwWaitHint = wait_hint;

    if (current_state == SERVICE_START_PENDING) {
        g_service_status.dwControlsAccepted = 0;
    } else {
        g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    if (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED) {
        g_service_status.dwCheckPoint = 0;
    } else {
        g_service_status.dwCheckPoint = check_point++;
    }

    SetServiceStatus(g_status_handle, &g_service_status);
}

static void WINAPI service_ctrl_handler(DWORD ctrl_code) {
    switch (ctrl_code) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        report_service_status(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        stop_trusttunnel_client();
        break;
    case SERVICE_CONTROL_INTERROGATE:
        report_service_status(g_service_status.dwCurrentState, NO_ERROR, 0);
        break;
    default:
        break;
    }
}

static void WINAPI service_main(DWORD argc, LPWSTR *argv) {
    (void) argc;
    (void) argv;
    g_status_handle = RegisterServiceCtrlHandlerW(SERVICE_NAME.data(), service_ctrl_handler);
    if (g_status_handle == nullptr) {
        return;
    }

    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwServiceSpecificExitCode = 0;

    report_service_status(SERVICE_START_PENDING, NO_ERROR, 10000);

    g_svc_running = true;
    int result = run_client(*g_svc_cli_args);
    g_svc_running = false;

    report_service_status(SERVICE_STOPPED, result == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR, 0);
}

static bool validate_config(const std::string &config_path) {
    toml::parse_result parse_result = toml::parse_file(config_path);
    if (!parse_result) {
        errlog(g_svc_logger, "Failed parsing configuration: {}", parse_result.error().description());
        return false;
    }

    std::optional config_res = TrustTunnelConfig::build_config(parse_result.table());
    if (!config_res) {
        errlog(g_svc_logger, "Failed to parse config");
        return false;
    }
    return true;
}

static std::optional<std::wstring> get_exe_path() {
    std::wstring buf(MAX_PATH, L'\0');
    DWORD len = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    if (len == 0) {
        errlog(g_svc_logger, "GetModuleFileNameW failed: error {}", GetLastError());
        return std::nullopt;
    }
    while (len == buf.size()) {
        buf.resize(buf.size() * 2);
        len = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (len == 0) {
            errlog(g_svc_logger, "GetModuleFileNameW failed: error {}", GetLastError());
            return std::nullopt;
        }
    }
    buf.resize(len);
    return buf;
}

static void print_usage_manual() {
    std::cout << "\nService 'TrustTunnelClient' installed successfully.\n\n"
              << "The service is configured to start automatically on boot.\n\n"
              << "To start/stop the service:\n"
              << "  cmd.exe:\n"
              << "    sc start TrustTunnelClient\n"
              << "    sc stop TrustTunnelClient\n"
              << "  PowerShell:\n"
              << "    Start-Service TrustTunnelClient\n"
              << "    Stop-Service TrustTunnelClient\n\n"
              << "To query service status:\n"
              << "  cmd.exe:\n"
              << "    sc query TrustTunnelClient\n"
              << "  PowerShell:\n"
              << "    Get-Service TrustTunnelClient\n\n"
              << "To disable auto-start:\n"
              << "  cmd.exe:\n"
              << "    sc config TrustTunnelClient start= demand\n"
              << "  PowerShell:\n"
              << "    Set-Service TrustTunnelClient -StartupType Manual\n";
}

static int service_install(const std::string &config_path) {
    if (!validate_config(config_path)) {
        return 1;
    }

    std::filesystem::path abs_config = std::filesystem::absolute(config_path);
    auto exe_path = get_exe_path();
    if (!exe_path) {
        return 1;
    }

    std::wstring image_path = L"\"" + *exe_path + L"\" --service-run --config \"" + abs_config.wstring() + L"\"";

    ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE)};
    if (!scm) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            errlog(g_svc_logger, "Administrator privileges required to install the service");
        } else {
            errlog(g_svc_logger, "Failed to open Service Control Manager: error {}", err);
        }
        return 1;
    }

    ScHandle svc{CreateServiceW(scm.get(), SERVICE_NAME.data(), SERVICE_DISPLAY_NAME.data(), SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, image_path.c_str(), nullptr, nullptr,
            nullptr, nullptr, nullptr)};
    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            errlog(g_svc_logger, "Service is already installed. Uninstall first to reinstall.");
        } else if (err == ERROR_ACCESS_DENIED) {
            errlog(g_svc_logger, "Administrator privileges required to install the service");
        } else {
            errlog(g_svc_logger, "Failed to create service: error {}", err);
        }
        return 1;
    }

    wchar_t svc_description[] = L"TrustTunnel VPN client service";
    SERVICE_DESCRIPTIONW desc = {};
    desc.lpDescription = svc_description;
    ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DESCRIPTION, &desc);

    if (!StartServiceW(svc.get(), 0, nullptr)) {
        DWORD err = GetLastError();
        warnlog(g_svc_logger, "Service installed but failed to start: error {}", err);
    }

    print_usage_manual();
    return 0;
}

static int service_uninstall() {
    ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!scm) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            errlog(g_svc_logger, "Administrator privileges required to uninstall the service");
        } else {
            errlog(g_svc_logger, "Failed to open Service Control Manager: error {}", err);
        }
        return 1;
    }

    ScHandle svc{
            OpenServiceW(scm.get(), SERVICE_NAME.data(), STANDARD_RIGHTS_DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS)};
    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            errlog(g_svc_logger, "Service is not installed");
        } else if (err == ERROR_ACCESS_DENIED) {
            errlog(g_svc_logger, "Administrator privileges required to uninstall the service");
        } else {
            errlog(g_svc_logger, "Failed to open service: error {}", err);
        }
        return 1;
    }

    SERVICE_STATUS status = {};
    if (QueryServiceStatus(svc.get(), &status) && status.dwCurrentState != SERVICE_STOPPED) {
        infolog(g_svc_logger, "Stopping running service...");
        if (!ControlService(svc.get(), SERVICE_CONTROL_STOP, &status)) {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_NOT_ACTIVE) {
                warnlog(g_svc_logger, "Failed to send stop control to service: error {}", err);
            }
        }

        constexpr int MAX_WAIT_MS = 10000;
        constexpr int POLL_INTERVAL_MS = 500;
        int waited_ms = 0;
        while (waited_ms < MAX_WAIT_MS) {
            Sleep(POLL_INTERVAL_MS);
            waited_ms += POLL_INTERVAL_MS;
            if (!QueryServiceStatus(svc.get(), &status)) {
                break;
            }
            if (status.dwCurrentState == SERVICE_STOPPED) {
                break;
            }
        }
        if (status.dwCurrentState != SERVICE_STOPPED) {
            warnlog(g_svc_logger, "Service did not stop within {} seconds", MAX_WAIT_MS / 1000);
        }
    }

    if (!DeleteService(svc.get())) {
        DWORD err = GetLastError();
        errlog(g_svc_logger, "Failed to delete service: error {}", err);
        return 1;
    }

    std::cout << "Service 'TrustTunnelClient' uninstalled successfully.\n";
    return 0;
}

static int service_run(const cxxopts::ParseResult *cli_args) {
    g_svc_cli_args = cli_args;

    wchar_t svc_name[] = L"TrustTunnelClient";
    SERVICE_TABLE_ENTRYW dispatch_table[] = {
            {svc_name, service_main},
            {nullptr, nullptr},
    };

    if (!StartServiceCtrlDispatcherW(dispatch_table)) {
        DWORD err = GetLastError();
        errlog(g_svc_logger, "StartServiceCtrlDispatcher failed: error {}", err);
        return 1;
    }

    return 0;
}

#endif // _WIN32
