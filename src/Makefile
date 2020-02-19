BINDIR := ../bin
CC := clang
LLC := llc
# CFLAGS := -O2 -emit-llvm -Wall -DDEBUG -Wno-unused-function -Wno-unused-label
CFLAGS := -O2 -emit-llvm -Wall -Wno-unused-function -Wno-unused-label

# CFLAGS := -O2 -emit-llvm -Wall
DEBUGFLAG :=
LLFLAGS := -march=bpf -filetype=obj
# CFLAGS := -O2 -target bpf -Wall -DDEBUG

CXX := clang++
CPPFLAGS := -std=c++14
OPTIMIZE := -O2
# CPPFLAGS += `pkg-config --cflags protobuf grpc`

PROTOC := protoc
GRPC_CPP_PLUGIN :=grpc_cpp_plugin
GRPC_CPP_PLUGIN_PATH ?= `which $(GRPC_CPP_PLUGIN)`
GRPCLIB := -L/usr/local/lib `pkg-config --libs protobuf grpc++`
GRPCFLAGS := `pkg-config --cflags protobuf grpc`

all: build

build: xnat_kern.o xnat_dump xnat_stats xnat controller
	mv $^ $(BINDIR)/

xnat_kern.o: xnat_kern.c
	$(CC) $(CFLAGS) $(DEBUGFLAG) -c $< -o -| $(LLC) $(LLFLAGS) -o $@
.PHONY: xnat_kern.o

xnat_stats: xnat_stats.cc
	$(CXX) $(CPPFLAGS) $(OPTIMIZE) -lbpf $< -o $@
.PHONY: xnat_stats

xnat: xnat.pb.o xnat.grpc.pb.o xnat.o
	$(CXX) $(OPTIMIZE) $^ -L/usr/local/lib `pkg-config --libs protobuf grpc++ libnl-3.0 libnl-route-3.0` -lbpf `pkg-config --libs libnl-3.0 libnl-route-3.0` -o $@
.PHONY: xnat

xnat_dump: xnat.pb.o xnat.grpc.pb.o xnat_dump.o
	$(CXX) $(OPTIMIZE) $^ $(GRPCLIB) -lbpf -lpcap -o $@
.PHONY: xnat_dump

controller: xnat.pb.o xnat.grpc.pb.o controller.o
	$(CXX) $(OPTIMIZE) $^ $(GRPCLIB) -o $@
.PHONY: controller


xnat.pb.o: xnat.pb.cc
	$(CXX) $(CPPFLAGS) $(OPTIMIZE) $(GRPCFLAGS) -c -o $@ $<
.PHONY: xnat.pb.o

xnat.grpc.pb.o: xnat.grpc.pb.cc
	$(CXX) $(CPPFLAGS) $(OPTIMIZE) $(GRPCFLAGS) -c -o $@ $<
.PHONY: xnat.grpc.pb.o

xnat.o: xnat.cc
	$(CXX) $(CPPFLAGS) $(OPTIMIZE) `pkg-config --cflags protobuf grpc libnl-3.0 libnl-route-3.0` -c -o $@ $<
.PHONY: xnat.o

xnat_dump.o: xnat_dump.cc
	$(CXX) $(CPPFLAGS) $(OPTIMIZE) $(GRPCFLAGS) -c -o $@ $<
.PHONY: xnat_dump.o

controller.o: controller.cc
	$(CXX) $(CPPFLAGS) $(OPTIMIZE) $(GRPCFLAGS) -c -o $@ $<
.PHONY: controller.o

.PRECIOUS: %.grpc.pb.cc
%.grpc.pb.cc: %.proto
	$(PROTOC) --grpc_out=. --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN_PATH) $<

.PRECIOUS: %.pb.cc
%.pb.cc: %.proto
	$(PROTOC) --cpp_out=.  $<

clean:
	-rm xnat_dump xnat_stats xnat *.o *.pb.cc *.pb.h

