FROM ubuntu:focal

RUN apt update && apt upgrade -y && apt install -y build-essential clang\
        && apt -y install linux-source-5.4.0 \
        && cd /usr/src \
        && tar xjf linux-source-5.4.0.tar.bz2 \
        && cp /usr/src/linux-source-5.4.0/include/uapi/linux/if_xdp.h /usr/include/linux/if_xdp.h \
        && cp /usr/src/linux-source-5.4.0/include/uapi/linux/if_link.h /usr/include/linux/if_link.h \
        && cp /usr/src/linux-source-5.4.0/include/uapi/linux/bpf.h /usr/include/linux/bpf.h \
        && apt install -y libelf-dev \
        && cd /usr/src/linux-source-5.4.0/tools/lib/bpf \
        && make  \
        && make install  \
        && make install_headers \
        && ln -sf /usr/local/lib64/libbpf.a /lib/libbpf.a \
        && ln -sf /usr/local/lib64/libbpf.so /lib/libbpf.so \
        && ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm \
        && apt clean \
        && rm -rf /var/lib/apt/lists/*

COPY . /xnat

CMD ["make"]
