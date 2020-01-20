# xnat

# Build, Install

```
apt install build-essential
apt install linux-source-<version>

tar xjf linux-source-<version>

cp /usr/src/linux-source-<version>/include/uapi/linux/if_xdp.h /usr/include/linux/if_xdp.h
cp /usr/src/linux-source-<version>/include/uapi/linux/if_link.h /usr/include/linux/if_link.h
cp /usr/src/linux-source-<version>/include/uapi/linux/bpf.h /usr/include/linux/bpf.h

apt install libelf-dev

cd /usr/linux-source-<version>/tools/lib/bpf

make 
make install 
make install_headers
ln -sf /usr/local/lib64/libbpf.a /lib/libbpf.a
ln -sf /usr/local/lib64/libbpf.so /lib/libbpf.so

# ??
ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```
