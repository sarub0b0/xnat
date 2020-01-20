
CC := clang
# CFLAGS := -O2 -target bpf -Wall -DDEBUG
# CFLAGS := -O2 -target bpf -Wall
CFLAGS := -O2 -target bpf -Wall -DDEBUG

all: xnat_kern xnat_user stats loader xnat_user

xnat_kern:
	$(CC) $(CFLAGS) -c xnat_kern.c -o xnat_kern.o
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
