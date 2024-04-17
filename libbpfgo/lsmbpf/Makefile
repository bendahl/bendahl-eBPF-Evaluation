PROGRAM=lsmbpf

.Phony: all clean vmlinux testenvironment-up testenvironment-down libbpfgo

all: clean vmlinux $(PROGRAM).bpf.o $(PROGRAM)

clean:
	rm -f vmlinux.h $(PROGRAM) $(PROGRAM).bpf.o

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(PROGRAM).bpf.o: $(PROGRAM).bpf.c vmlinux.h
	clang -g -O2 -c -target bpf -o $(PROGRAM).bpf.o $(PROGRAM).bpf.c

$(PROGRAM): libbpfgo main.go go.mod
	CC=clang CGO_CFLAGS="-I $(abspath ../libbpfgo/output)" CGO_LDFLAGS="$(abspath ../libbpfgo/output/libbpf.a)" go build -ldflags="-extldflags=-static" -tags osusergo,netgo -o $(PROGRAM)

libbpfgo:
	$(MAKE) -C ../libbpfgo libbpfgo-static

testenvironment-up:
	vagrant up
	vagrant reload

testenvironment-down:
	vagrant destroy -f
