# Preliminaries

* Install packages
  ```bash
  sudo apt update
  
  # Contiki-NG-related stuff
  sudo apt install ant build-essential curl default-jdk doxygen git net-tools pip rlwrap srecord wireshark
  pip install pyserial
  
  # Keystone-related stuff
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
    python \
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
    p7zip-full
  
  # libcoap-related stuff
  sudo apt install cmake graphviz libcunit1-dev libtool
  ```
* Clone repositories
  ```bash
  # switch to a directory where you like to store your repositories in
  
  # Contiki-NG
  git clone https://github.com/kkrentz/contiki-ng.git
  cd contiki-ng
  git checkout -b filtering origin/filtering
  git submodule update --init --recursive
  cd ..
  
  # Keystone
  git clone https://github.com/kkrentz/filtering-keystone.git
  
  # Proxy code
  git clone https://github.com/kkrentz/filtering-proxy.git
  cd filtering-proxy
  git submodule update --init --recursive
  cd ..
  
  # Example IoT client
  git clone https://github.com/kkrentz/libcoap-minimal.git
  ```
* Add this to `~/.bashrc`:
  ```bash
  export JAVA_HOME="/lib/jvm/java-11-openjdk-amd64"
  export KEYSTONE_DIR=<path to filtering-keystone>
  export RISCV=$KEYSTONE_DIR/riscv64
  export PATH=$RISCV/bin:$PATH
  export KEYSTONE_SDK_DIR=$KEYSTONE_DIR/sdk/build64
  export SM_DIR=$KEYSTONE_DIR/sm
  export PROXY_DIR=<path to filtering-proxy>
  export LIBCOAP_RISCV_DIR=<path to contiki-ng>/os/net/app-layer/libcoap/riscv
  export LD_LIBRARY_PATH=/usr/local/lib
  export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
  ```
* Close all terminals so that the changes take effect  
* Set up Keystone:
  ```bash
  cd $KEYSTONE_DIR
  unset KEYSTONE_SDK_DIR
  ./fast-setup.sh
  export KEYSTONE_SDK_DIR=$KEYSTONE_DIR/sdk/build64
  ```
* Build Keystone:
  ```bash
  cd $KEYSTONE_DIR
  mkdir build \
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
  Note: Do not worry if tests fail
* Build libcoap:
  ```bash 
  cd <path to contiki-ng>/os/net/app-layer/libcoap/
  ./autogen.sh \
    && ./configure \
      --disable-doxygen \
      --disable-manpages \
      --disable-dtls \
      --without-epoll \
      --disable-examples \
      --disable-examples-source \
      --disable-tcp \
      --enable-oscore \
    && make -j$(nproc) \
    && sudo make install \
    && ./cross-compile.sh
  ```
# Virtual Test Environment

## Middlebox in QEMU

* Compile proxy code and start QEMU:
  ```bash
  cd $PROXY_DIR \
    && ./quick-start.sh \
    && cd $KEYSTONE_DIR/build \
    && mkdir -p overlay/etc/network \
    && cp $PROXY_DIR/overlay/interfaces overlay/etc/network/ \
    && cp $PROXY_DIR/build/filtering-host-app.* overlay/root/ \
    && cp $PROXY_DIR/build/eyrie-rt overlay/root/ \
    && cp $PROXY_DIR/build/filtering_enclave/filtering_enclave.eapp_riscv overlay/root/ \
    && cp $PROXY_DIR/overlay/run.sh overlay/root/ \
    && make image -j$(nproc) \
    && sudo ./scripts/run-qemu.sh
  ```
* Log in as `root` with password `sifive`.
* Once logged in, run:
  ```bash
  ./run.sh
  ```
  Note: You can stop QEMU using CTRL+A,X
* Establish network connection with QEMU:
  ```bash
  cd $PROXY_DIR && ./connect.sh
  ```

## Filtering Client in Cooja

* Start Cooja:
  ```bash
  cd <path to contiki-ng>/tools/cooja
  ant run
  ```
* Open the simulation `<path to contiki-ng>/examples/filtering/basic.csc` and start it.
* Open a terminal and run:
  ```bash
  cd <path to contiki-ng>/examples/filtering/aggregator/
  make connect-router-cooja TARGET=cooja
  ```
* To check if everything is fine, ping the aggregator and the IoT device like so:
  ```bash
  ping6 fd00::ff:fe00:1
  ping6 fd00::ff:fe00:2
  ```

Note: Cooja can also be started like so:
```bash
cd <path to contiki-ng>/tools/cooja/dist/
java -jar cooja.jar -quickstart=../../../examples/filtering/basic.csc 
```

Note: For quick tests without an aggregator, simply run:
```bash
cd <path to contiki-ng>/examples/filtering/iot-device
make TARGET=native iot-device -j${nproc} && sudo ./iot-device.native
```

## IoT Client in Linux

```bash
cd <path to libcoap-minimal>
make -j${nproc}
./client
```
Note: `client.cc` contains hardcoded addresses. These need to be adapted when changing the default addresses.

# Physical Test Environment
* As for flashing OpenMotes, see https://gist.github.com/kkrentz/18ce317d0a1db331ccc38be6c7e0ac9e.
