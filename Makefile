BPFDIR := bpf
TESTDIR := test

all: utils bpf test

$(shell mkdir -p bin)

bpf:
	$(MAKE) -C $(BPFDIR)
.PHONY: bpf

utils:
	mkdir -p build
	cd build; cmake .. && make -j --no-print-directory && make install --no-print-directory
.PHONY: utils

test:
	$(MAKE) -C $(TESTDIR)
.PHONY: test

clean: bpf_clean test_clean utils_clean
	-rm -rf bin

utils_clean:
	-rm -rf build

bpf_clean:
	$(MAKE) -C $(BPFDIR) clean

test_clean:
	$(MAKE) -C $(TESTDIR) clean

env:
	ip link add link ens192 name ens192.100 type vlan id 100
	ip link add link ens224 name ens224.300 type vlan id 300
	ip addr add 10.10.0.1/24 dev ens192.100
	ip addr add 10.30.0.1/24 dev ens224.300
	ip link set ens192.100 up
	ip link set ens224.300 up
