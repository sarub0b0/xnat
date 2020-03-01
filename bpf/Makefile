BINDIR := ../bin

CC := clang
LLC := llc

# CFLAGS := -O2 -emit-llvm -Wall -DDEBUG -Wno-unused-function -Wno-unused-label
CFLAGS := -O2 -emit-llvm -Wall -Wno-unused-function -Wno-unused-label
# CFLAGS := -O2 -emit-llvm -Wall -Wno-unused-function -Wno-unused-label
#
INC := -I../include

LLCFLAGS := -march=bpf -filetype=obj

all: build

build: xnat_kern.o
	mv $^ $(BINDIR)/

xnat_kern.o: xnat_kern.c
	$(CC) $(CFLAGS) $(DEBUGFLAG) $(INC) -c $< -o -| $(LLC) $(LLCFLAGS) -o $@
.PHONY: xnat_kern.o

clean:
	-rm *.o

