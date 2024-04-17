/*
This program implements a simple load balancer, using direct server return (DSR) as a load balancing strategy.
Only TCP packets are handled by this program.
As a load balancing algorithm, round robin is used.
*/
package main

import (
	_ "embed"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"

	"gopkg.in/yaml.v3"
)

// program configuration (read from file)
type config struct {
	ListenIf string   `yaml:"listenInterface"`
	TcpPort  uint16   `yaml:"tcp_port"`
	Backends []string `yaml:"backends"`
}

// special compiler directive to tell the go tool to embed this object file in the resulting binary
//
//go:embed loadbalancer.bpf.o
var bpfobject []byte

// This is the main entrypoint of the program
func main() {
	// parse config file
	rawConfigBytes, err := os.ReadFile("config.yml")
	if err != nil {
		log.Fatalf("failed to read config.yml file: %v", err)
	}

	// unmarshal config file to configuration structure above
	cfg := new(config)
	err = yaml.Unmarshal(rawConfigBytes, &cfg)
	if err != nil {
		log.Fatalf("failed to unmarshal configuration: %v", err)
	}

	// get the network interface to listen on
	listenInterface, err := net.InterfaceByName(cfg.ListenIf)
	if err != nil {
		log.Fatalf("unkonwn listen interface: %v", listenInterface)
	}
	log.Printf("listening on interface %v\n", listenInterface.Name)

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Load pre-compiled programs and maps into the kernel.
	bpfModule, err := libbpfgo.NewModuleFromBuffer(bpfobject, "loadbalancer.bpf.o")
	if err != nil {
		log.Fatalf("failed to load bpf module from file: %v", err)
	}
	defer bpfModule.Close()

	// load BPF ojbects
	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatalf("failed to load bpf module: %v", err)
	}

	// load and attach BPF program
	loadbalancer, err := bpfModule.GetProgram("xdp_loadbalancer")
	if err != nil {
		log.Fatalf("failed to get bpf program: %v", err)
	}
	bpflink, err := loadbalancer.AttachXDP(listenInterface.Name)
	if err != nil {
		log.Fatalf("failed to attach xdp program: %v", err)
	}
	if bpflink.FileDescriptor() == 0 {
		log.Fatalf("invalid bpflink file descriptor '0'")
	}

	// initialize settings map
	settings, err := bpfModule.GetMap("settings")
	if err != nil {
		log.Fatalf("failed to load settings map: %v", err)
	}
	initSettings(cfg, settings)

	// populate list of backends
	backends, err := bpfModule.GetMap("backends")
	if err != nil {
		log.Fatalf("failed to load backends map: %v", err)
	}
	initBackends(cfg, backends)

	<-stopper
}

// initBackends populates the BPF map that holds the list of backends used for load balancing
func initBackends(cfg *config, backends *libbpfgo.BPFMap) {
	for i, backend := range cfg.Backends {
		addr, err := net.ParseMAC(backend)
		if err != nil {
			log.Fatalf("failed to parse mac: %v: %v", backend, err)
		}
		var addrArr [6]byte
		copy(addrArr[:], addr[:6])
		err = backends.Update(toPtr(uint32(i)), toPtr(addrArr))
		if err != nil {
			log.Fatalf("failed to initialize backends: %v", err)
		}
	}
}

// initSettings populates the BPF map that holds the global program parameters
func initSettings(cfg *config, settings *libbpfgo.BPFMap) {
	err := settings.Update(toPtr(bpfSettingPORT), toPtr(cfg.TcpPort))
	if err != nil {
		log.Fatalf("failed to set port of backends in settings map: %v", err)
	}

	numberBackends := len(cfg.Backends)
	err = settings.Update(toPtr(bpfSettingNO_BACKENDS), toPtr(uint16(numberBackends)))
	if err != nil {
		log.Fatalf("failed to set number of backends in settings map: %v", err)
	}

	outIf, err := net.InterfaceByName(cfg.ListenIf)
	if err != nil {
		log.Fatalf("failed to get interface index for outbound interface: %v", err)
	}

	err = settings.Update(toPtr(bpfSettingOUT_IF), toPtr(uint16(outIf.Index)))
	if err != nil {
		log.Fatalf("failed to set number of backends in settings map: %v", err)
	}
}

// convert given value to a raw pointer
func toPtr[E any](e E) unsafe.Pointer {
	return unsafe.Pointer(&e)
}
