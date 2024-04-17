/*
This program implements a simple Linux Security Module (LSM).
It inhibits using chroot to the host's filesystem root in order
to prevent container escapes and privilege escalation.
*/
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// special compiler directive that triggers code generation when `go generate is invoked`
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type setting -target amd64 bpf lsmbpf.bpf.c

// This is the main entrypoint to the program
func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer func(objs *bpfObjects) {
		err := objs.Close()
		if err != nil {
			log.Fatalf("failed to properly clean up bpf objects: %v", err)
		}
	}(&objs)

	// attach BPF program to system hook
	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: objs.LsmNoChrootToRoot})
	if err != nil {
		log.Fatalf("attaching lsm failed: %s", err)
	}
	defer lsmLink.Close()

	// use linux-specific stat syscall to determine inode and device of given file
	var stat = syscall.Stat_t{}
	err = syscall.Stat("/proc/self/ns/pid", &stat)
	if err != nil {
		log.Fatalf("failed to retrieve info from proc fs: %v", err)
	}

	// set configuration values in BPF map
	err = objs.Settings.Put(bpfSettingINODE, stat.Ino)
	if err != nil {
		log.Fatalf("failed to set inode: %v", err)
	}
	err = objs.Settings.Put(bpfSettingDEV, stat.Dev)
	if err != nil {
		log.Fatalf("failed to set dev: %v", err)
	}

	// wait for termination signal
	<-stopper

}
