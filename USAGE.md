# LiteBox Usage Guide

LiteBox is a security-focused library OS that sandboxes applications by drastically reducing the interface to the host. This guide covers the main commands available and how to use them.

## Overview

LiteBox provides several command-line tools for different use cases and platforms:

- **litebox-runner-linux-userland** - Run Linux programs with LiteBox on unmodified Linux
- **litebox-packager** - Package Linux ELF programs for execution under LiteBox
- **litebox_syscall_rewriter** - Rewrite binaries for LiteBox execution
- **litebox-broker-userland** - Broker process for managing LiteBox sessions
- Platform-specific runners for Windows, SEV SNP, LVBS, and OP-TEE

## Building LiteBox

### Prerequisites

- Rust toolchain (latest stable)
- Standard build tools (gcc, make, etc.)
- For some features: `ldd` (for dependency discovery)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/microsoft/litebox.git
cd litebox

# Build all default projects
cargo build --release

# Build a specific binary
cargo build --release --bin litebox-packager
cargo build --release --bin litebox-runner-linux-userland

# Run tests
cargo test
```

The compiled binaries will be in `target/release/`.

## Core Commands

### 1. litebox-packager

Package Linux ELF programs for execution under LiteBox. Discovers shared library dependencies, rewrites ELF files using the syscall rewriter, and produces a `.tar` suitable for use with `litebox-runner-linux-userland`.

#### Host Mode (Local Files)

Packages local ELF files along with their dependencies:

```bash
# Package a single executable
litebox-packager -o output.tar /usr/bin/python3

# Package multiple files
litebox-packager -o myapp.tar /path/to/app /path/to/config

# Include extra files (non-ELF files included as-is)
litebox-packager -o bundle.tar /usr/bin/bash \
  --include /etc/passwd:/etc/passwd \
  --include /etc/group:/etc/group

# Skip rewriting specific files
litebox-packager -o bundle.tar /usr/bin/python3 \
  --no-rewrite /lib/x86_64-linux-gnu/libc.so.6

# Verbose output
litebox-packager -o output.tar /usr/bin/python3 --verbose
```

#### OCI Container Mode

Pull and package a container image from a registry:

```bash
# Package a container image (public registries only)
litebox-packager --oci-image docker.io/library/alpine:latest \
  -o alpine-bundle.tar

# Package a specific registry image
litebox-packager --oci-image docker.io/library/ubuntu:22.04 \
  -o ubuntu.tar

# With verbose output to see extraction progress
litebox-packager --oci-image docker.io/library/python:3.11 \
  -o python-bundle.tar --verbose
```

#### Options

- `-o, --output PATH` - Output tar file path (default: `litebox_packager.tar`)
- `--include HOST_PATH:TAR_PATH` - Include extra files (format: host path to tar path, split on first colon)
- `--no-rewrite PATH` - Skip rewriting specific files by absolute path
- `-v, --verbose` - Print verbose output during packaging
- `--oci-image IMAGE_REF` - Pull and package container image instead of local files

### 2. litebox-runner-linux-userland

Run Linux programs with LiteBox on unmodified Linux. Provides a sandboxed execution environment.

#### Basic Usage

```bash
# Run a simple command
litebox-runner-linux-userland /bin/echo "Hello from LiteBox"

# Run a program with arguments
litebox-runner-linux-userland /usr/bin/python3 --version

# Run a shell
litebox-runner-linux-userland /bin/bash
```

#### With Environment Variables

```bash
# Pass environment variables to the program
litebox-runner-linux-userland /usr/bin/env \
  --env PATH=/usr/bin:/bin \
  --env HOME=/root \
  --env DEBUG=1

# Forward existing environment variables
litebox-runner-linux-userland -Z /bin/bash --forward-env

# Mix explicit variables and forwarded environment
litebox-runner-linux-userland /usr/bin/python3 \
  --env APP_CONFIG=/config/app.conf \
  --forward-env
```

#### With File System Setup (Unstable)

These options require the `-Z`/`--unstable` flag:

```bash
# Initialize with pre-filled files
litebox-runner-linux-userland -Z /usr/bin/python3 \
  --initial-files /path/to/bundle.tar

# Insert individual files into filesystem
litebox-runner-linux-userland -Z /bin/bash \
  --insert-file /path/to/config.txt

# Load program from tar instead of host filesystem
litebox-runner-linux-userland -Z /bin/app \
  --initial-files /path/to/bundle.tar \
  --program-from-tar
```

#### With Syscall Rewriting (Unstable)

Apply syscall rewriting on-the-fly:

```bash
# Rewrite syscalls at runtime
litebox-runner-linux-userland -Z /path/to/binary \
  --rewrite-syscalls
```

#### Logging

Control detailed logging via `LITEBOX_LOG` environment variable:

```bash
# Debug level logging
LITEBOX_LOG=debug litebox-runner-linux-userland /bin/bash

# Specific module logging
LITEBOX_LOG=litebox=debug,litebox::fs=trace \
  litebox-runner-linux-userland /usr/bin/python3

# Multiple filters
LITEBOX_LOG=litebox::executor=info,litebox::pipe=debug \
  litebox-runner-linux-userland /bin/sh
```

#### Full Example: Package and Run

```bash
# 1. Package an application
litebox-packager -o myapp.tar /usr/bin/python3 \
  --include /path/to/script.py:/app/script.py

# 2. Run it in the sandbox
litebox-runner-linux-userland -Z /usr/bin/python3 \
  --initial-files myapp.tar \
  --program-from-tar \
  /app/script.py
```

### 3. litebox_syscall_rewriter

Rewrite binary files for LiteBox execution by hooking `syscall` instructions.

#### Rewriting ELF Binaries

```bash
# Rewrite an x86-64 ELF binary
litebox_syscall_rewriter /path/to/binary -o /path/to/binary.rewritten

# Rewrite an AArch64 ELF binary
litebox_syscall_rewriter /path/to/aarch64-binary \
  -o /path/to/aarch64-binary.rewritten
```

#### Rewriting Windows PE Binaries

```bash
# Rewrite a Windows PE binary
litebox_syscall_rewriter /path/to/app.exe \
  -o /path/to/app.rewritten.exe
```

#### Specifying Custom Trampolines

```bash
# Use a custom trampoline address
litebox_syscall_rewriter /path/to/binary \
  -o /path/to/binary.rewritten \
  --trampoline 0x7fffffff0000
```

#### Supported Architectures

- **x86-64 ELF** - Full syscall hooking support
- **x86-64 PE** - Syscall hooking + Windows TEB rewriting
- **AArch64 ELF** - Syscall hooking + thread-pointer virtualization (Linux-host only)

### 4. litebox-broker-userland

Manages LiteBox sessions and resource allocation.

```bash
# Start the broker
litebox-broker-userland

# The broker creates Unix sockets for runner communication
# Runners connect to the broker to manage resources
```

## Platform-Specific Runners

### Windows Userland

Run LiteBox on Windows:

```bash
litebox-runner-windows-userland program.exe [args]
```

### Windows on Linux

Run Windows programs on Linux via LiteBox:

```bash
litebox-runner-windows-on-linux-userland app.exe [args]
```

### Linux on Windows

Run Linux programs on Windows via LiteBox:

```bash
litebox-runner-linux-on-windows-userland /bin/bash
```

### SEV SNP (Secure Encrypted Virtualization)

Run programs in an SNP-protected environment:

```bash
litebox-runner-snp [program]
```

### LVBS (Lightweight Virtualization Backend)

Run with LVBS backend (requires custom target and nightly):

```bash
# Requires: cargo +nightly build -Z build-std --target <custom-target>
litebox-runner-lvbs [program]
```

### OP-TEE

Run on OP-TEE trusted execution environment:

```bash
litebox-runner-optee-on-linux-userland [program]
```

## Development and Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p litebox_broker_core

# Run tests with logging
LITEBOX_LOG=debug cargo test -- --nocapture

# Run integration tests
cargo test --test '*'
```

### Building for Specific Platforms

```bash
# Build for LVBS (requires nightly and custom toolchain)
cargo +nightly build -Z build-std --target=<lvbs-target>

# Cross-compile for AArch64
cargo build --target aarch64-unknown-linux-gnu
```

### Working with Custom Targets

Some runners require custom LLVM targets. Check individual crate documentation:

```bash
# Build configuration examples
rustflags="-C link-arg=..." cargo build --target=custom
```

## Common Workflows

### Sandbox a Python Application

```bash
# 1. Package Python and your app
litebox-packager -o python-app.tar /usr/bin/python3 \
  --include /path/to/app.py:/app/app.py \
  --include /path/to/requirements.txt:/app/requirements.txt

# 2. Run in sandbox
litebox-runner-linux-userland -Z /usr/bin/python3 \
  --initial-files python-app.tar \
  --program-from-tar \
  /app/app.py
```

### Sandbox a Web Server

```bash
# Package nginx
litebox-packager -o nginx.tar /usr/sbin/nginx \
  --include /etc/nginx:/etc/nginx \
  --include /usr/share/nginx:/usr/share/nginx

# Run in sandbox
litebox-runner-linux-userland -Z /usr/sbin/nginx \
  --initial-files nginx.tar \
  --program-from-tar \
  --env PORT=8080 \
  /usr/sbin/nginx -g "daemon off;"
```

### Package and Run from Container Image

```bash
# Create a self-contained bundle from Alpine
litebox-packager --oci-image docker.io/library/alpine:latest \
  -o alpine-bundle.tar

# Run it
litebox-runner-linux-userland -Z /bin/sh \
  --initial-files alpine-bundle.tar \
  --program-from-tar
```

### Debug with Logging

```bash
# Set up debugging
export LITEBOX_LOG=litebox=debug,litebox::executor=trace

# Run with detailed output
litebox-runner-linux-userland /bin/bash -c "echo test"
```

## Troubleshooting

### Common Issues

**Issue: Permission denied when running litebox-runner-linux-userland**

```bash
# Ensure binaries are executable
chmod +x target/release/litebox-runner-linux-userland

# Run with elevated privileges if needed
sudo target/release/litebox-runner-linux-userland /bin/bash
```

**Issue: Dependency discovery fails in litebox-packager**

```bash
# Explicitly include all dependencies
litebox-packager -o output.tar /usr/bin/app \
  --include /lib/x86_64-linux-gnu/libc.so.6:/lib/libc.so.6 \
  --include /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2:/lib/ld.so

# Or run ldd manually to find dependencies
ldd /usr/bin/app
```

**Issue: Binary has unpatchable syscalls**

```bash
# Check for dynamically generated syscalls
# These cannot be patched and may cause issues
# Consider recompiling without JIT or dynamic code generation
```

## Environment Variables

### LITEBOX_LOG

Controls logging output level:

```bash
# Levels: error, warn, info, debug, trace
LITEBOX_LOG=info litebox-runner-linux-userland /bin/bash

# Multiple modules with different levels
LITEBOX_LOG=litebox::fs=trace,litebox::executor=debug \
  litebox-runner-linux-userland /bin/bash
```

### Other Configuration

Platform-specific environment variables may be available. Check individual runner documentation.

## Advanced Topics

### Working with Broker Resource Limits

The broker enforces per-session and global resource quotas:

- Maximum live object references
- Maximum total pipe capacity
- Per-session reference quota
- Per-session pipe capacity quota

Configure via the broker implementation or environment.

### Custom Syscall Trampolines

Advanced users can specify custom trampoline addresses:

```bash
litebox_syscall_rewriter /path/to/binary \
  -o /path/to/binary.rewritten \
  --trampoline 0x400000000
```

### Integration with CI/CD

LiteBox can be integrated into CI pipelines:

```bash
# Test a containerized app
litebox-packager --oci-image myregistry/myapp:latest -o test.tar
litebox-runner-linux-userland -Z /app/test \
  --initial-files test.tar \
  --program-from-tar
```

## Getting Help

- Check `--help` on any command for detailed usage
- Review individual crate README files
- See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup
- Report issues on GitHub

## Examples by Use Case

### Sandboxing Untrusted Code

```bash
litebox-packager -o untrusted.tar /usr/bin/python3 \
  --include /path/to/untrusted-script.py:/script.py

litebox-runner-linux-userland -Z /usr/bin/python3 \
  --initial-files untrusted.tar \
  --program-from-tar \
  --forward-env \
  /script.py
```

### Running on Multiple Platforms

```bash
# Linux
litebox-runner-linux-userland ./app arg1 arg2

# Windows (on Windows machine)
litebox-runner-windows-userland ./app.exe arg1 arg2

# Windows binary on Linux (requires cross-platform setup)
litebox-runner-windows-on-linux-userland ./app.exe arg1 arg2
```

### Headless Container Execution

```bash
litebox-packager --oci-image docker.io/library/ubuntu:22.04 \
  -o ubuntu.tar

litebox-runner-linux-userland -Z /bin/bash \
  --initial-files ubuntu.tar \
  --program-from-tar \
  -c "apt update && apt install -y my-package"
```
