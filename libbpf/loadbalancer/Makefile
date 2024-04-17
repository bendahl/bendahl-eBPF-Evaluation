.Phony: all clean build testenvironment-up testenvironment-down

all: clean build

clean:
	rm -rf build/ *.skel.h vmlinux.h loadbalancer

build:
	cmake -S . -B ./build && cmake --build ./build && cp ./build/loadbalancer .

testenvironment-up:
	vagrant up

testenvironment-down:
	vagrant destroy -f
