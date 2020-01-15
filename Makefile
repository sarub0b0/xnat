
CC := clang
CFLAGS := -O2 -target bpf -Wall -DDEBUG
# CFLAGS := -g -target bpf -Wall

all: xnat_int_kern xnat_ext_kern stats loader loader_int loader_ext xnat_int_user

xnat_int_kern:
	$(CC) $(CFLAGS) -c xnat_int_kern.c -o xnat_int_kern.o
.PHONY: xnat_int_kern

xnat_ext_kern:
	$(CC) $(CFLAGS) -c xnat_ext_kern.c -o xnat_ext_kern.o
.PHONY: xnat_ext_kern

xnat_int_user:
	$(CC) xnat_int_user.c -o xnat_int_user -lbpf
.PHONY: xnat_int_user

stats:
	$(CC) stats.c -o stats -lbpf
.PHONY: stats

loader:
	$(CC) loader.c -o loader -lbpf
.PHONY: loader

loader_int:
	$(CC) loader_int.c -o loader_int -lbpf
.PHONY: loader_int

loader_ext:
	$(CC) loader_ext.c -o loader_ext -lbpf
.PHONY: loader_ext


clean:
	-rm stats loader loader_int loader_ext *.o



