
CC := clang
LLC := llc
# CFLAGS := -O2 -target bpf -Wall -DDEBUG
CFLAGS := -O2 -emit-llvm -Wall -DDEBUG
DEBUGFLAG := -g
LLFLAGS := -march=bpf -filetype=obj
# CFLAGS := -O2 -target bpf -Wall -DDEBUG

CXX := clang++
CPPFLAGS := -O2 -std=c++14 -stdlib=libc++ -g
# CPPFLAGS += `pkg-config --cflags protobuf grpc`

PROTOC := protoc
GRPC_CPP_PLUGIN :=grpc_cpp_plugin
GRPC_CPP_PLUGIN_PATH ?= `which $(GRPC_CPP_PLUGIN)`

all: xnat_kern xnat_stats xnat_dump xnat

xnat_kern:
	$(CC) $(CFLAGS) $(DEBUGFLAG) -c xnat_kern.c -o -| $(LLC) $(LLFLAGS) -o xnat_kern.o
.PHONY: xnat_kern

xnat_stats:
	$(CXX) $(CPPFLAGS) xnat_stats.cc -o xnat_stats -lbpf
.PHONY: xnat_stats

xnat: xnat.pb.o xnat.grpc.pb.o xnat.o
	$(CXX) $^ -L/usr/local/lib `pkg-config --libs protobuf grpc++` -lpthread -lbpf -o $@
.PHONY: xnat

xnat_dump: xnat.pb.o xnat.grpc.pb.o xnat_dump.o
	$(CXX) $^ -L/usr/local/lib `pkg-config --libs protobuf grpc++` -lpthread -lbpf -lpcap -o $@
.PHONY: xnat_dump

xnat.pb.o: xnat.pb.cc
	clang++ -std=c++14 `pkg-config --cflags protobuf grpc` -c -o xnat.pb.o xnat.pb.cc

xnat.grpc.pb.o: xnat.grpc.pb.cc
	clang++ -std=c++14 `pkg-config --cflags protobuf grpc` -c -o xnat.grpc.pb.o xnat.grpc.pb.cc

xnat.o:
	clang++ -std=c++14 `pkg-config --cflags protobuf grpc` -c -o xnat.o xnat.cc
.PHONY: xnat.o

xnat_dump.o:
	clang++ -std=c++14 `pkg-config --cflags protobuf grpc` -c -o xnat_dump.o xnat_dump.cc
.PHONY: xnat_dump.o


.PRECIOUS: %.grpc.pb.cc
%.grpc.pb.cc: %.proto
	$(PROTOC) --grpc_out=. --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN_PATH) $<

.PRECIOUS: %.pb.cc
%.pb.cc: %.proto
	$(PROTOC) --cpp_out=.  $<


clean:
	-rm xnat_dump xnat_stats xnat *.o *.pb.cc *.pb.h


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

