# TrustTunnel client

`tt-client` contains the native TrustTunnel client libraries, platform
adapters, and console client. It connects to a self-hosted
[tt-server](https://github.com/moreprivate/tt-server) and can carry TCP, UDP,
and ICMP traffic through a system tunnel or local SOCKS5 listener.

Deployment scripts are in [tt-manage](https://github.com/moreprivate/tt-manage);
the Flutter application is in
[tt-mobile](https://github.com/moreprivate/tt-mobile).

## Components

- C++ protocol and VPN libraries
- Linux, macOS, and Windows console clients
- Android, Apple, and Windows native adapters
- Configurable upstream DNS and routing policies
- Android Maven/AAR packaging consumed by `tt-mobile`

This repository does not derive country lists or configure a router. Country
split routing, dnsmasq, UCI, LAN forwarding, and OpenWrt fail-closed policy
are implemented by `tt-manage/tt-client-openwrt.sh`.

## Use a release

Create a profile with `tt-server.sh add-user`, then install it on a Linux
host:

```sh
git clone https://github.com/moreprivate/tt-manage.git
cd tt-manage
sudo sh tt-client-linux.sh install --config ./client.toml --version RELEASE_TAG
```

For an OpenWrt router, use `tt-client-openwrt.sh` instead. The same TOML can
be used by the console client, OpenWrt client, or mobile app. Keep it private:
it contains credentials and endpoint verification settings.

## Build from source

Native prerequisites and platform instructions are in
[DEVELOPMENT.md](DEVELOPMENT.md):

```sh
make init
EXPORT_DIR=bin make build_and_export_bin
```

The reproducible multi-target workflow is
`.github/workflows/build-client-targets.yml`. It builds Linux targets and
the Android library archive, then publishes checksummed assets. It is normally
invoked by the `tt-manage` release chain after the server build.

For a local end-to-end server/client/mobile build, run `make build-router` or
`make build` from `tt-manage`; that chain supplies the pinned Docker
toolchain and exports artifacts under `../.tt-build`.

## Configuration

The server-generated TOML supplies the endpoint address, custom SNI,
credentials, certificate verification, transport, and connection count:

```toml
upstream_protocol = "http2"       # auto, http2, or http3
http_connections_num = 0          # client default when zero
```

Do not disable certificate verification in production. See
[trusttunnel/README.md](trusttunnel/README.md) for the complete configuration
reference and [platform/README.md](platform/README.md) for adapter integration.

## Development checks

```sh
make init
make lint
```

## License

Apache 2.0. See [LICENSE](LICENSE).
