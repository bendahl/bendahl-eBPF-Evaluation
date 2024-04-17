.Phony: all clean build testenvironment-up testenvironment-down

all: clean build

clean:
	rm -rf build/ *.skel.h vmlinux.h lsmbpf

build:
	cmake -S . -B ./build && cmake --build ./build && cp ./build/lsmbpf .

testenvironment-up:
	vagrant up
	vagrant reload

testenvironment-down:
	vagrant destroy -f
