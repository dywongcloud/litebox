# macOS ARM End-to-End Boxer Test

This example demonstrates building and running a boxer container on macOS Apple Silicon (ARM64) without requiring root privileges.

## Constraints

**RUN commands require root** because they execute inside a chroot during the build phase. On macOS, chroot has restrictions even with `sudo`. For a rootless build and test on macOS ARM, we use `FROM + CMD` without `RUN`.

## Building

```sh
cd examples/macos-arm-test
../../target/release/boxer build -o test.box.wasm -f Dockerfile
```

This pulls `alpine:latest` (requires Docker registry access) and creates a `.box.wasm` file containing:
- The Alpine rootfs with all binaries pre-rewritten by LiteBox's syscall rewriter
- Metadata (platform, entrypoint, environment, etc.)

## Running

```sh
../../target/release/boxer run test.box.wasm
```

Expected output:
```
Boxer works on macOS ARM!
```

## With RUN commands (requires root)

If you need `RUN` instructions (package installation, etc.), invoke boxer with `sudo`:

```sh
sudo ../../target/release/boxer build -o test-with-run.box.wasm -f Dockerfile.with-run
```

But for development and testing on macOS, the rootless approach above is recommended:
1. Build multi-stage images on your build host (with full toolchain)
2. Use `COPY --from=...` to bring build artifacts into a minimal rootless runtime stage
3. Build the final boxer container on macOS without RUN commands

## Example: Multi-stage build (rootless)

```dockerfile
# This part runs on your build host (with full toolchain)
FROM golang:latest as builder
WORKDIR /build
COPY . .
# RUN go build -o myapp    # Run this OUTSIDE boxer

# This part runs rootless in boxer on macOS ARM
FROM alpine:latest
COPY --from=builder /build/myapp /app/
ENTRYPOINT ["/app"]
```

1. Run the builder stage locally: `docker build --target builder -o out .`
2. Copy the artifact into your build context
3. Build the rootless runtime stage with boxer: `boxer build -o app.box.wasm`
