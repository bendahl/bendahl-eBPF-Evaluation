.Phony: all clean build build-ebpf build-ebpf-release release testenvironment-up testenvironment-down

all: clean build release

clean:
	cargo clean

build-ebpf:
	cargo xtask build-ebpf

build-ebpf-release:
	cargo xtask build-ebpf --release

build: build-ebpf
	cargo build

release: build-ebpf-release
	cargo build --release

testenvironment-up:
	vagrant up

testenvironment-down:
	vagrant destroy -f
