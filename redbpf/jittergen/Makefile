# enable multiline shell commands in make
.ONESHELL:

.Phony: all build-bpf build clean

all: clean build

build-bpf:
	cd ./probes
	# use rust 1.60 to ensure the build works correctly
	cargo +1.60 bpf build --target-dir=../target
	cd ..

build: build-bpf
	# use rust 1.60 to ensure the build works correctly
	cargo +1.60 build
	cp ./target/debug/jittergen .

clean: 
	cargo clean
	cargo clean --manifest-path ./probes/Cargo.toml
	rm -f ./jittergen
	
testenvironment-up:
	vagrant up

testenvironment-down:
	vagrant destroy -f
