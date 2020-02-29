FROM ubuntu:focal

RUN apt update && apt upgrade -y

RUN apt install -y \
        build-essential \
        clang \
        libc6-dev-i386 \
        llvm \
        libc++-dev \
        libgrpc++-dev \
        libgrpc-dev \
        libprotobuf-dev \
        libpcap-dev \
        protobuf-compiler \
        protobuf-compiler-grpc \
        pkg-config \
        cppcheck \
        googletest \
        cmake \
        libnl-3-dev

RUN apt -y install linux-source-5.4.0 \
        && cd /usr/src \
        && tar xjf linux-source-5.4.0.tar.bz2 \
        && cp /usr/src/linux-source-5.4.0/include/uapi/linux/if_xdp.h /usr/include/linux/if_xdp.h \
        && cp /usr/src/linux-source-5.4.0/include/uapi/linux/if_link.h /usr/include/linux/if_link.h \
        && cp /usr/src/linux-source-5.4.0/include/uapi/linux/bpf.h /usr/include/linux/bpf.h \
        && apt install -y libelf-dev \
        && cd /usr/src/linux-source-5.4.0/tools/lib/bpf \
        && make -j \
        && make install \
        && make install_headers \
        && ln -sf /usr/local/lib64/libbpf.a /lib/libbpf.a \
        && ln -sf /usr/local/lib64/libbpf.so /lib/libbpf.so \
        && ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm \
        && cd /usr/src/googletest/ \
        && mkdir build \
        && cd build \
        && cmake .. \
        && make -j \
        && make install \
        && apt clean \
        && rm -rf /var/lib/apt/lists/*

