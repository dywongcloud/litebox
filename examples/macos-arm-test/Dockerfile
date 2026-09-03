
# Example Dockerfile for testing boxer on macOS ARM
# This demonstrates building and running a container without RUN commands
# (RUN requires root/chroot; use FROM + CMD for rootless execution)

FROM alpine:latest

# Set a simple command that works without requiring package installation
CMD ["/bin/sh", "-c", "echo 'Boxer works on macOS ARM!'"]
