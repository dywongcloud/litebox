<!-- Copyright (c) Microsoft Corporation.
     Licensed under the MIT license. -->

# XFCE desktop guest

This recipe builds an Alpine 3.24 XFCE desktop for the macOS userland runner
and serves its 1024×768 framebuffer and input through the built-in browser
viewer.

Apple's kernel clears AArch64 `x18` whenever it returns to userspace. Stock
Alpine allocates that register, which silently corrupts ld.so, Xorg, GTK, and
XFCE hot loops under native guest execution. The build therefore first runs
`../../scripts/build-x18-desktop-repo.sh`; that rebuilds the desktop's loaded
code closure with x18 reserved and refuses to publish any runtime ELF that
still disassembles to an `x18`/`w18` operand.

```sh
./litebox_packager/examples/xfce/build-xfce-image.sh /tmp/litebox-xfce.tar

cargo run --release -p litebox_runner_linux_on_macos_userland -- \
  --unstable --guest-root \
  --initial-files /tmp/litebox-xfce.tar \
  --vnc-web 6080 -- \
  /usr/bin/start-desktop.sh
```

Open <http://127.0.0.1:6080/>. The canvas accepts pointer, wheel, and keyboard
input.

The first package build is intentionally substantial and resumable. Successful
aports origins remain in the retained `litebox-x18-repo-build` container;
rerunning retries only unfinished origins. Override paths and names with:

- `LITEBOX_X18_DESKTOP_REPO`
- `LITEBOX_ALPINE_BRANCH`
- `LITEBOX_XFCE_IMAGE_TAG`

The recipe disables GLX and fbdev ShadowFB because those unimplemented paths
do not update litebox's browser framebuffer. It also appends the synthetic
`/sys/class/graphics/fb0/device/subsystem` link required by Xorg's fbdevhw
probe; the packager otherwise intentionally omits `/sys` from OCI rootfs
images.
