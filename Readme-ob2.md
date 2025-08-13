# i.MX DDoS Blocker for OrangeBox2.0

This document describes how to build this prject for OrangeBox2.0 board.

## Build project
### DPDK SDK
This project depends on DPDK. The DPDK SDK should be built first.

```bash
mkdir ~/Software/SDK/dpdk-22.11-imx943-sdk

# Set up cross-compliation env. CROSS_PATH points to your toolchain path
export CROSS_PATH=~/Software/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-linux-gnu/bin
export PATH=$PATH:$CROSS_PATH
export CC=aarch64-none-linux-gnu-g++
export GCC=aarch64-none-linux-gnu-gcc

git clone https://github.com/nxp-qoriq/dpdk.git
cd dpdk

meson setup arm64-build --cross-file config/arm/arm64_imx_linux_gnu_gcc -Dprefix=~/Software/SDK/dpdk-22.11-imx943-sdk
cd arm64-build
meson compile
meson install
```

### Build l2capfwd
Switch to this project folder.
```
cd imx-ddos-blocker/sources
```

Please check the path in `env_setup_imx943` and modify them as your DPDK SDK and toolchain path.
```
export DPDK_PKG_PATH=~/Software/SDK/dpdk-22.11-imx943-sdk/lib/pkgconfig
...
export CROSS_PATH=~/Software/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-linux-gnu/bin
```

If the path is correct, run `source env_setup_imx943`.
Make project:
```
make
cd ..
./generate_delivery.sh
```

You will get `board_deploy` folder and copy this folder to OrangeBox2.0 board.