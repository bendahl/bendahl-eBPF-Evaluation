/*
    This program implements a simple Linux Security Module (LSM).
    It inhibits using chroot to the host's filesystem root in order 
    to prevent container escapes and privilege escalation.
*/
package main

import (
	_ "embed"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
)

// embed BPF program in resulting program binary
//go:embed lsmbpf.bpf.o
var bpfobject []byte

type bpfSetting uint32

const (
	bpfSettingINODE bpfSetting = 0
	bpfSettingDEV   bpfSetting = 1
)

// this is the main entrypoint to the program
func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Load pre-compiled programs and maps into the kernel.
	bpfModule, err := libbpfgo.NewModuleFromBuffer(bpfobject, "lsmbpf.bpf.o")
	if err != nil {
		log.Fatalf("failed to load bpf module from file: %v", err)
	}
	defer bpfModule.Close()

	// load BPF objects
	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatalf("failed to load bpf module: %v", err)
	}

	// load and attach BPF program 
	lsm, err := bpfModule.GetProgram("lsm_no_chroot_to_root")
	if err != nil {
		log.Fatalf("failed to get bpf program: %v", err)
	}
	lsmLink, err := lsm.AttachLSM()
	if err != nil {
		log.Fatalf("failed to attach lsm: %v", err)
	}
	if lsmLink.FileDescriptor() == 0 {
		log.Fatalf("invalid bpflink file descriptor '0'")
	}

	// initialize settings map
	settings, err := bpfModule.GetMap("settings")
	if err != nil {
		log.Fatalf("failed to load default config map: %v", err)
	}
	// use linux-specific stat syscall to determine inode and device of given file
	var stat = syscall.Stat_t{}
	err = syscall.Stat("/proc/self/ns/pid", &stat)
	if err != nil {
		log.Fatalf("failed to retrieve info from proc fs: %v", err)
	}

	// populate settings map
	err = settings.Update(toPtr(bpfSettingINODE), toPtr(stat.Ino))
	if err != nil {
		log.Fatalf("failed to set inode: %v", err)
	}
	err = settings.Update(toPtr(bpfSettingDEV), toPtr(stat.Dev))
	if err != nil {
		log.Fatalf("failed to set device: %v", err)
	}

	// wait for signal
	<-stopper
}

// convert given value to raw pointer
func toPtr[E any](e E) unsafe.Pointer {
	return unsafe.Pointer(&e)
}
