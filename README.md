# xnat

ubuntu 20.04で動作確認

# Build, Install

```
apt update && apt upgrade -y

#################################################
# xdpのプログラムだけなら
# 以下の3つのパッケージをインストール
#################################################

apt install -y build-essential
apt install -y libelf-dev
apt install -y libc6-dev-i386

#########################################

apt install -y             \
    clang                  \
    libc6-dev-i386         \
    llvm                   \
    libc++-dev             \
    libgrpc++-dev          \
    libgrpc-dev            \
    libprotobuf-dev        \
    libpcap-dev            \
    protobuf-compiler      \
    protobuf-compiler-grpc \
    pkg-config             \
    cppcheck               \
    googletest             \
    cmake                  \
    libnl-3-dev            \
    libnl-route-3-dev


#########################################
# OSのkernelバージョンに合わせて変更する
#########################################
apt -y install linux-source-5.4.0

cd /usr/src 
tar xjf linux-source-5.4.0.tar.bz2 

cp /usr/src/linux-source-5.4.0/include/uapi/linux/if_xdp.h /usr/include/linux/if_xdp.h 
cp /usr/src/linux-source-5.4.0/include/uapi/linux/if_link.h /usr/include/linux/if_link.h 
cp /usr/src/linux-source-5.4.0/include/uapi/linux/bpf.h /usr/include/linux/bpf.h 


############################
# build libbpf
############################
cd /usr/src/linux-source-5.4.0/tools/lib/bpf

make -j 
make install 
make install_headers 

ln -sf /usr/local/lib64/libbpf.a /lib/libbpf.a 
ln -sf /usr/local/lib64/libbpf.so /lib/libbpf.so 
ln -sf /usr/local/lib64/libbpf.so /lib/libbpf.so.0 

############################
# build googletest
############################
cd /usr/src/googletest/
mkdir build 

cd build 
cmake ..
make -j 
make install 

############################
# compileエラーが出る場合
############################
ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```
