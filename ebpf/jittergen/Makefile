.Phony: all clean bpfgen build testenvironment-up testenvironment-down

all: clean bpfgen build

clean:
	rm -f bpf_bpfel_x86.* jittergen *.log

bpfgen:
	go generate

build:
	CGO_ENABLED=0 go build

testenvironment-up:
	vagrant up

testenvironment-down:
	vagrant destroy -f
