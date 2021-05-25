This repository contains the two central components of our TEE-assisted remote denial-of-sleep defense, namely the Filtering host app and TEE. Other components are scattered across these repositories:

* https://github.com/kkrentz/contiki-ng
* https://github.com/kkrentz/libcoap
* https://github.com/kkrentz/filtering-keystone
* https://github.com/kkrentz/micro-ecc
* https://github.com/kkrentz/libcoap-minimal

We also use tinyalloc (&copy; 2016 - 2017 Karsten Schmidt - Apache Software License 2.0).

Please find our paper [here](https://doi.org/10.1007/978-3-031-30122-3_24).

# Getting Started

## Installing Dependencies

```bash
sudo apt install autoconf \
  automake \
  build-essential \
  curl \
  doxygen \
  git \
  libtool \
  makeself \
  net-tools \
  openjdk-21-jdk \
  pip \
  pkg-config \
  rlwrap \
  srecord \
  wireshark
```
Download and extract [GCC](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads).

Download and extract [Gradle](https://gradle.org/releases/), too.

## Cloning Repositories

Switch to a directory where you like to store the repositories in.

```bash
git clone https://github.com/kkrentz/contiki-ng.git
pushd contiki-ng
git submodule update --init --recursive
popd
git clone https://github.com/kkrentz/filtering-keystone.git
pushd filtering-keystone
git submodule update --init --recursive
popd
git clone https://github.com/kkrentz/filtering-proxy.git
pushd filtering-proxy
git submodule update --init --recursive
popd
git clone https://github.com/kkrentz/libcoap-minimal.git
```

## Setting up Environment Variables

Add this to `~/.bashrc`:

```bash
export CNG_PATH=<path to contiki-ng>
export KEYSTONE_PATH=<path to filtering-keystone>
export FILTERING_PROXY_PATH=<path to filtering-proxy>
export LIBCOAP_PATH=$HOME/libcoap
export LD_LIBRARY_PATH=$LIBCOAP_PATH/lib
export PKG_CONFIG_PATH=$LIBCOAP_PATH/lib/pkgconfig
PATH=<path to gradle>/bin:$PATH
PATH=<path to GCC>/bin:$PATH
```

`CNG_PATH` and `KEYSTONE_PATH` are only used within the bash snippets of this README.

## Building Keystone

For an introduction to Keystone's build system, see [here](https://docs.google.com/document/d/1yyUPx0PWyk3NjuQ4uYNBLyASri5MvxqsotZce_cPfwU/edit).

```bash
cd $KEYSTONE_PATH && make
```

For inspecting build errors, run `less build-generic64/build.log`. It sometimes already helps to clean a package. This cleans the most relevant packages:

```bash
make BUILDROOT_TARGET=filtering-libcoap-dirclean \
  && make BUILDROOT_TARGET=filtering-proxy-dirclean \
  && make BUILDROOT_TARGET=keystone-bootrom-dirclean \
  && make BUILDROOT_TARGET=keystone-sm-dirclean \
  && make BUILDROOT_TARGET=host-keystone-sdk-dirclean \
  && make BUILDROOT_TARGET=keystone-driver-dirclean \
  && make BUILDROOT_TARGET=keystone-examples-dirclean \
  && make BUILDROOT_TARGET=opensbi-dirclean
```

One can switch between different remote attestation protocols like so:

```bash
# SIGn-then-MAc (SIGMA)-based remote attestation
make KEYSTONE_ATTESTATION=sigma
# Tiny Remote Attestation Protocol (TRAP)
make KEYSTONE_ATTESTATION=trap
# Implicit Remote Attestation Protocol (IRAP)
make KEYSTONE_ATTESTATION=irap
```
IRAP is the default.

## Building libcoap

```bash
cd $CNG_PATH/os/net/app-layer/libcoap/ \
  && ./autogen.sh \
  && ./configure \
    --prefix=$LIBCOAP_PATH \
    --disable-documentation \
    --disable-dtls \
    --with-epoll \
    --disable-examples \
    --disable-examples-source \
    --disable-tcp \
    --disable-oscore \
    --enable-oscore-ng \
    --disable-q-block \
  && make -j$(nproc) \
  && make install
```

## Running the Middlebox in QEMU

```bash
cd $KEYSTONE_PATH \
  && pushd build-generic64 \
  && rm -rf overlay/root/.ssh \
  && mkdir -p overlay/etc/network \
  && cp $FILTERING_PROXY_PATH/overlay/interfaces overlay/etc/network/ \
  && popd \
  && make \
  && sudo ip tuntap add dev tap0 mode tap user $USER \
  && make run
```

Log in as `root` with password `sifive`.

Once logged in, run:

```bash
./run.sh
```

Note: You can stop QEMU using CTRL+A,X

To establish a network connection with QEMU:

```bash
cd $FILTERING_PROXY_PATH && ./connect.sh
```

## Running Filtering Clients in Cooja

Copy the output of `./run.sh` to `$CNG_PATH/os/services/filtering/filtering-client.c`.

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

To check if networking works, ping the border router and the IoT device like so:

```bash
ping6 fd00::ff:fe00:1
ping6 fd00::ff:fe00:2
```

For switching remote attestation protocols, go to `$CNG_PATH/examples/filtering/*/project-conf.h`, and adapt `WITH_TRAP` and `WITH_IRAP` accordingly. For running IRAP with mutual attestation, go to `$CNG_PATH/examples/filtering/*/Makefile` and uncomment `MODULES += os/services/tiny-dice`. This will enable the mock-up of TinyDICE.

## Running an OSCORE-NG Client

```bash
cd <path to libcoap-minimal>
make -j${nproc}
./client
```

## Running Filtering Clients on OpenMotes

* As for flashing OpenMotes, see [here](https://gist.github.com/kkrentz/18ce317d0a1db331ccc38be6c7e0ac9e).

Note: `client.cc` and `smor-l3.c` contain hardcoded addresses. These need to be adapted to the real hardware.
