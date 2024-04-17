/*
This program implements a simple load balancer, using direct server return (DSR) as a load balancing strategy.
Only TCP packets are handled by this program.
As a load balancing algorithm, round robin is used.
*/
package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"

	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
)

// configuration data structure
type config struct {
	ListenIf string   `yaml:"listenInterface"`
	TcpPort  uint16   `yaml:"tcp_port"`
	Backends []string `yaml:"backends"`
}

// special compiler directive that triggers code generation when `go generate is invoked`
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type setting -type tcp_session -target amd64 bpf loadbalancer.bpf.c

// This is the main entrypoint to the program
func main() {
	// parse configuration file
	rawConfigBytes, err := os.ReadFile("config.yml")
	if err != nil {
		log.Fatalf("failed to read config.yml file: %v", err)
	}

	// unmarshal configuration file data to above structure
	cfg := new(config)
	err = yaml.Unmarshal(rawConfigBytes, &cfg)
	if err != nil {
		log.Fatalf("failed to unmarshal configuration: %v", err)
	}

	// get network interface id by name
	listenInterface, err := net.InterfaceByName(cfg.ListenIf)
	if err != nil {
		log.Fatalf("unkonwn listen interface: %v", listenInterface)
	}
	log.Printf("listening on interface %v\n", listenInterface.Name)

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

	// attach BPF program to selected nic
	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadbalancer,
		Interface: listenInterface.Index,
	})
	if err != nil {
		log.Fatalf("failed to attach xdp probe: %v", err)
	}
	defer func(xdp link.Link) {
		err := xdp.Close()
		if err != nil {
			log.Printf("failed to close xpd program properly: %v\n", err)
		}
	}(xdp)

	// populate BPF settings maps with configuration values
	initSettings(cfg, objs)
	initBackends(cfg, objs)

	<-stopper
}

// initBackends populates the BPF map that holds the list of target backends
func initBackends(cfg *config, objs bpfObjects) {
	for i, backend := range cfg.Backends {
		addr, err := net.ParseMAC(backend)
		if err != nil {
			log.Fatalf("failed to parse mac: %v: %v", backend, err)
		}
		var addrArr [6]byte
		copy(addrArr[:], addr[:6])
		err = objs.Backends.Put(uint32(i), addrArr)
		if err != nil {
			log.Fatalf("failed to initialize backends: %v", err)
		}
	}
}

// initSettings populates the BPF map that holds the main settings
func initSettings(cfg *config, objs bpfObjects) {
	err := objs.Settings.Put(bpfSettingPORT, cfg.TcpPort)
	if err != nil {
		log.Fatalf("failed to set port of backends in settings map: %v", err)
	}

	numberBackends := len(cfg.Backends)
	err = objs.Settings.Put(bpfSettingNO_BACKENDS, uint16(numberBackends))
	if err != nil {
		log.Fatalf("failed to set number of backends in settings map: %v", err)
	}

	outIf, err := net.InterfaceByName(cfg.ListenIf)
	if err != nil {
		log.Fatalf("failed to get interface index for outbound interface: %v", err)
	}

	err = objs.Settings.Put(bpfSettingOUT_IF, uint16(outIf.Index))
	if err != nil {
		log.Fatalf("failed to set number of backends in settings map: %v", err)
	}
}
