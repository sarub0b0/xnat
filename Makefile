SRCDIR := src
TESTDIR := test

all:
	cd $(shell pwd)/$(SRCDIR); make
	cd $(shell pwd)/$(TESTDIR); make

main:
	cd $(shell pwd)/$(SRCDIR); make

test:
	cd $(shell pwd)/$(TESTDIR); make

clean: main_clean test_clean
	-rm -rf bin/*

main_clean:
	cd $(shell pwd)/$(SRCDIR); make clean

test_clean:
	cd $(shell pwd)/$(TESTDIR); make clean

env:
	ip link add link ens192 name ens192.100 type vlan id 100
	ip link add link ens224 name ens224.300 type vlan id 300
	ip addr add 10.10.0.1/24 dev ens192.100
	ip addr add 10.30.0.1/24 dev ens224.300
	ip link set ens192.100 up
	ip link set ens224.300 up
