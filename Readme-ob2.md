# i.MX DDoS Blocker for OrangeBox2.0

This document describes how to build this prject for OrangeBox2.0 board.

## Build project
### DPDK SDK
This project depends on DPDK. The DPDK SDK should be built first.

```bash
sudo apt update
sudo apt install meson

mkdir ~/SDK/dpdk-22.11-imx943-sdk

# Set up cross-compliation env using Yocto toolchain
source <path-to-toolchain>/environment-setup-armv8a-poky-linux

git clone https://github.com/nxp-qoriq/dpdk.git
cd dpdk

meson setup arm64-build --cross-file config/arm/arm64_imx_poky_linux_gcc -Dprefix=~/SDK/dpdk-22.11-imx943-sdk
cd arm64-build
meson compile
meson install
```

### Build l2capfwd
Switch to this project folder.
```
cd imx-ddos-blocker/sources
```

Modify PKG_CONFIG according to your DPDK SDK path.
```
export DPDK_PKG_PATH=~/SDK/dpdk-22.11-imx943-sdk/lib/pkgconfig
export PKG_CONFIG_PATH=$DPDK_PKG_PATH:$PKG_CONFIG_PATH
```

Make project:
```
make
cd ..
./generate_delivery.sh
```

You will get `board_deploy` folder and copy this folder to OrangeBox2.0 board.