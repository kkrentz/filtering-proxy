This repository contains the central component of our TEE-assisted remote denial-of-sleep defense: the Filtering TEE. Other components are scattered across these repositories:

* https://github.com/kkrentz/contiki-ng
* https://github.com/kkrentz/libcoap
* https://github.com/kkrentz/filtering-keystone
* https://github.com/kkrentz/micro-ecc
* https://github.com/kkrentz/libcoap-minimal

# Installing Dependencies

## Contiki-NG-related packages

```bash
sudo apt install ant \
  build-essential \
  curl \
  doxygen \
  git \
  net-tools \
  openjdk-17-jdk \
  pip \
  rlwrap \
  srecord \
  wireshark
pip install pyserial
```
Install the [ARM compiler](https://docs.contiki-ng.org/en/develop/doc/getting-started/Toolchain-installation-on-Linux.html).
Download and extract [Gradle](https://gradle.org/releases/), too.

## Keystone-related packages

```bash
sudo apt install autoconf \
  automake \
  autotools-dev \
  bc \
  bison \
  build-essential \
  curl \
  expat \
  libexpat1-dev \
  flex \
  gawk \
  gcc \
  git \
  gperf \
  libgmp-dev \
  libmpc-dev \
  libmpfr-dev \
  libtool \
  texinfo \
  tmux \
  patchutils \
  zlib1g-dev \
  wget \
  bzip2 \
  patch \
  vim-common \
  lbzip2 \
  pkg-config \
  libglib2.0-dev \
  libpixman-1-dev \
  libssl-dev \
  screen \
  device-tree-compiler \
  expect \
  makeself \
  unzip \
  cpio \
  rsync \
  cmake \
  p7zip-full \
  ninja-build
```

# Cloning Repositories

Switch to a directory where you like to store your repositories in.

## Contiki-NG

```bash
git clone https://github.com/kkrentz/contiki-ng.git
cd contiki-ng
git submodule update --init --recursive
cd ..
```

## Keystone

```bash
git clone https://github.com/kkrentz/filtering-keystone.git
```

## Proxy code

```bash
git clone https://github.com/kkrentz/filtering-proxy.git
```

## Example OSCORE-NG client

```bash
git clone https://github.com/kkrentz/libcoap-minimal.git
```

# Building

## Environment Variables

Add this to `~/.bashrc`:

```bash
export CNG_PATH=<path to contiki-ng>
export KEYSTONE_DIR=<path to filtering-keystone>
export RISCV=$KEYSTONE_DIR/riscv64
export PATH=$RISCV/bin:$PATH
export PATH=<path to gradle>/bin:$PATH
export KEYSTONE_SDK_DIR=$KEYSTONE_DIR/sdk/build64
export SM_DIR=$KEYSTONE_DIR/sm
export PROXY_DIR=<path to filtering-proxy>
export LIBCOAP_DIR=$CNG_PATH/os/net/app-layer/libcoap/riscv
export LD_LIBRARY_PATH=/usr/local/lib
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

Do not forget to restart terminals so that the changes take effect.

## Keystone

Set up Keystone:

```bash
cd $KEYSTONE_DIR \
  && unset KEYSTONE_SDK_DIR \
  && ./fast-setup.sh \
  && export KEYSTONE_SDK_DIR=$KEYSTONE_DIR/sdk/build64
```

Build Keystone:

```bash
cd $KEYSTONE_DIR
mkdir -p build \
  && cd build \
  && cmake .. \
  && make image -j$(nproc) \
  && make buildroot -j$(nproc) \
  && make qemu -j$(nproc) \
  && make linux -j$(nproc) \
  && make sm -j$(nproc) \
  && make bootrom -j$(nproc) \
  && make driver -j$(nproc) \
  && make tests -j$(nproc) \
  && make image -j$(nproc) \
  && make run-tests
```

## libcoap

Switch to branch "old-build-system" and run `./cross-compile.sh`.

Then, switch back to branch "develop" and run:

```bash 
cd $CNG_PATH/os/net/app-layer/libcoap/ \
  && ./autogen.sh \
  && ./configure \
    --disable-documentation \
    --disable-dtls \
    --with-epoll \
    --disable-examples \
    --disable-examples-source \
    --disable-tcp \
    --enable-oscore-ng \
    --disable-q-block \
  && make -j$(nproc) \
  && sudo make install
```

# Running Everything Virtually

## Middlebox in QEMU

Compile proxy code and start QEMU:

```bash
cd $PROXY_DIR \
  && ./quick-start.sh \
  && cd $KEYSTONE_DIR/build \
  && mkdir -p overlay/etc/network \
  && cp $PROXY_DIR/overlay/interfaces overlay/etc/network/ \
  && cp $PROXY_DIR/build/filtering-proxy.ke overlay/root/ \
  && cp $PROXY_DIR/overlay/run.sh overlay/root/ \
  && make image -j$(nproc) \
  && sudo ./scripts/run-qemu.sh
```

Log in as `root` with password `sifive`.

Once logged in, run:

```bash
./run.sh
```

Note: You can stop QEMU using CTRL+A,X

Establish network connection with QEMU:

```bash
cd $PROXY_DIR && ./connect.sh
```

## Filtering Client in Cooja

Start Cooja:

```bash
cd $CNG_PATH/tools/cooja \
  && gradle run --args='../../examples/filtering/basic.csc'
```

Open a terminal and run:

```bash
cd $CNG_PATH/examples/filtering/aggregator/ \
  && make TARGET=openmote BOARD=openmote-cc2538 BOARD_REVISION=REV_A1 savetarget \
  && make connect-router-cooja
```
To check if everything is fine, ping the border router and the IoT device like so:

```bash
ping6 fd00::ff:fe00:1
ping6 fd00::ff:fe00:2
```

## OSCORE-NG Client in Linux

```bash
cd <path to libcoap-minimal>
make -j${nproc}
./client
```

Note: `client.cc` contains hardcoded addresses. These need to be adapted when changing the default addresses.

# Running Everything Physically

* As for flashing OpenMotes, see [here](https://gist.github.com/kkrentz/18ce317d0a1db331ccc38be6c7e0ac9e).

# Third-Party Library

We use tinyalloc (&copy; 2016 - 2017 Karsten Schmidt - Apache Software License 2.0 (see [LICENSE](./LICENSE))).

# Further Reading

* Please find our paper [here](https://doi.org/10.1007/978-3-031-30122-3_24)
