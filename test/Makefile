
all: build

build: test_xnat_kern

test_xnat_kern:
	clang++ -O2 --std=c++14 test_xnat_kern.cc -o test_xnat_kern -lgtest -lgtest_main -lpthread

clean:
	-rm test_xnat_kern *.o

