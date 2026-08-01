# TrustTunnel client

Cross-platform TrustTunnel client libraries, native platform adapters, and the
console client. The client connects to a self-hosted TrustTunnel server and can
tunnel TCP, UDP, and ICMP traffic through a system tunnel or SOCKS5 listener.

Project repositories:

- Server: <https://github.com/moreprivate/tt-server>
- Mobile app: <https://github.com/moreprivate/tt-mobile>
- This repository: <https://github.com/moreprivate/tt-client>

## Components

- C++ client libraries and protocol implementation
- Linux/macOS/Windows console client
- Android, Apple, and Windows platform adapters
- Split routing and configurable DNS upstreams

## Use a released console client

Generate a client configuration on the server, then use the manager on the
target Linux host:

```bash
git clone https://github.com/moreprivate/tt-manage.git
cd tt-manage
sudo ./tt-client-linux.sh install --config ./client.toml --version <release-tag>
```

For router installation and policy management, use `tt-manage`:

<https://github.com/moreprivate/tt-manage>

## Build from source

```bash
make init
EXPORT_DIR=bin make build_and_export_bin
```

The build requires Python, CMake, LLVM/Clang, Conan 2, Rust, and Ninja. Exact
versions and platform-specific setup are documented in
[`DEVELOPMENT.md`](DEVELOPMENT.md).

Native adapter details are in [`platform/README.md`](platform/README.md).

## Configuration

The server exports the credentials and endpoint settings required by the
client. Keep certificate verification enabled. For the console client, the
exported TOML can be passed directly to the client configuration option.

## Development checks

```bash
make init
make lint
```

See [`DEVELOPMENT.md`](DEVELOPMENT.md), platform adapter documentation, and
[`CHANGELOG.md`](CHANGELOG.md) for details.

## License

Apache 2.0. See [`LICENSE`](LICENSE).
