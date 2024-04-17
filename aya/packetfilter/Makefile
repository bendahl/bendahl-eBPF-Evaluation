# enable multiline shell commands in make
.ONESHELL:

.Phony: all clean build build-ebpf build-ebpf-release release testenvironment-up testenvironment-down

all: clean build release

clean:
	cargo clean

build-ebpf: vmlinux
	cargo xtask build-ebpf

build-ebpf-release:
	cargo xtask build-ebpf --release

build: build-ebpf
	cargo build

vmlinux:
	aya-tool generate in6_addr > packetfilter-ebpf/src/vmlinux.rs

release: build-ebpf-release
	cargo build --release

testenvironment-up:
	vagrant up

testenvironment-down:
	vagrant destroy -f
