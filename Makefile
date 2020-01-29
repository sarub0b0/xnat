
CC := clang
LLC := llc
# CFLAGS := -O2 -target bpf -Wall -DDEBUG
CFLAGS := -O2 -emit-llvm -Wall
DEBUGFLAG := -g
LLFLAGS := -march=bpf -filetype=obj
# CFLAGS := -O2 -target bpf -Wall -DDEBUG

all: xnat_kern xnat_user stats loader xnat_user

xnat_kern:
	$(CC) $(CFLAGS) $(DEBUGFLAG) -c xnat_kern.c -o -| $(LLC) $(LLFLAGS) -o xnat_kern.o
.PHONY: xnat_kern

xnat_user:
	$(CC) xnat_user.c -o xnat_user -lbpf
.PHONY: xnat_user

stats:
	$(CC) stats.c -o stats -lbpf
.PHONY: stats

loader:
	$(CC) loader.c -o loader -lbpf
.PHONY: loader

clean:
	-rm stats loader xnat_user *.o

init:
	-ip link add ingress_xnat type veth peer name host0
	-ip link add egress_xnat type veth peer name host1
	-ip netns add ingress
	-ip netns add egress
	-ip link set host0 netns ingress
	-ip link set host1 netns egress
	-ip addr add 192.168.0.1/24 brd + dev ingress_xnat
	-ip addr add 192.168.1.1/24 brd + dev egress_xnat
	-ip netns exec ingress ip addr add 192.168.0.2/24 brd + dev host0
	-ip netns exec egress ip addr add 192.168.1.2/24 brd + dev host1
	-ip link set ingress_xnat up
	-ip link set egress_xnat up
	-ip netns exec ingress ip link set host0 up
	-ip netns exec egress ip link set host1 up
	-ip netns exec ingress ip route add default via 192.168.0.1

