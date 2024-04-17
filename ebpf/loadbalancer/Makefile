.Phony: all clean vmlinux bpfgen build testenvironment-up testenvironment-down

all: clean vmlinux bpfgen build

clean:
	rm -f bpf_bpfel_x86.* vmlinux.h loadbalancer *.log

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpfgen:
	go generate

build:
	go build

testenvironment-up:
	vagrant up

testenvironment-down:
	vagrant destroy -f
