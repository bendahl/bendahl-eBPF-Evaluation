# enable multiline shell commands in make
.ONESHELL:

.Phony: all clean build testenvironment-up testenvironment-down

all: clean build

clean:
	rm -rf target/ *.skel.rs vmlinux.h *.log loadbalancer

build:
	cargo build 
	cp ./target/debug/loadbalancer .

testenvironment-up:
	vagrant up
	vagrant reload

testenvironment-down:
	vagrant destroy -f
