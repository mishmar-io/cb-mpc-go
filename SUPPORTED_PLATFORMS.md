# Supported Platforms

| Operating System | Architectures        | Status            |
| ---------------- | -------------------- | ----------------- |
| Linux            | amd64                | Supported         |
| macOS (Darwin)   | amd64, arm64 (Apple) | Supported         |
| Windows          | n/a                  | Unsupported (TBD) |

Linux/amd64 underpins our CI runs and the published Docker images. macOS (both Intel and Apple Silicon) is supported for native development; the scripts auto-detect the host CPU and build matching artifacts.

Windows is currently unsupported. The package requires CGO and uses build tags `//go:build cgo && !windows` to enforce this at compile-time. Attempting to build on Windows will result in compilation errors. Non-CGO builds (e.g., setting `CGO_ENABLED=0`) are also unsupported and will fail at compile-time.

Basic utility functions like version information (`cbmpc.WrapperVersion()`, `cbmpc.UpstreamVersion()`) and curve enums are available on all platforms except Windows.
