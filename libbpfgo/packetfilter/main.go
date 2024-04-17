/*
    This program implements a simple XDP-based packet filter that allows/blocks ip packets from predefined source addresses.
    The configuration is done via a yaml-file.
    Filtering rules are stored in BPF maps, so that the BPF program that performs the actual packet filtering can read and apply them.
*/
package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"gopkg.in/yaml.v3"
)

// special compiler directive to tell the go tool to embed the object file into the resulting binary
//
//go:embed packetfilter.bpf.o
var bpfobject []byte

const ALLOW = "allow"
const BLOCK = "block"

// configuration file structure is mapped to the below nested struct
type config struct {
	Rules struct {
		Interface string `yaml:"interface"`
		IPv4      struct {
			Default string   `yaml:"default"`
			Allow   []string `yaml:"allow"`
			Block   []string `yaml:"block"`
		} `yaml:"ipv4"`
		IPv6 struct {
			Default string   `yaml:"default"`
			Allow   []string `yaml:"allow"`
			Block   []string `yaml:"block"`
		} `yaml:"ipv6"`
	} `yaml:"rules"`
}

// This is the main entrypoint to the program
func main() {
	// parse config file
	rawConfigBytes, err := os.ReadFile("config.yml")
	if err != nil {
		log.Fatalf("failed to read config.yml file: %v", err)
	}

	// unmarshal file to the above structure
	cfg := new(config)
	err = yaml.Unmarshal(rawConfigBytes, &cfg)
	if err != nil {
		log.Fatalf("failed to unmarshal configuration: %v", err)
	}

	// set the network interface to listen on
	listenInterface, err := net.InterfaceByName(cfg.Rules.Interface)
	if err != nil {
		log.Fatalf("unkonwn interface: %v", listenInterface)
	}
	log.Printf("Using interface %v\n", listenInterface.Name)

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Load pre-compiled programs and maps into the kernel.
	bpfModule, err := libbpfgo.NewModuleFromBuffer(bpfobject, "packetfilter.bpf.o")
	if err != nil {
		log.Fatalf("failed to load bpf module from file: %v", err)
	}
	defer bpfModule.Close()

	// load BPF objects
	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatalf("failed to load bpf module: %v", err)
	}

	// attach the xdp program to the specified network interface
	packetfilter, err := bpfModule.GetProgram("xdp_prog_func")
	if err != nil {
		log.Fatalf("failed to get bpf program: %v", err)
	}
	bpflink, err := packetfilter.AttachXDP(listenInterface.Name)
	if err != nil {
		log.Fatalf("failed to attach xdp program: %v", err)
	}
	if bpflink.FileDescriptor() == 0 {
		log.Fatalf("invalid bpflink file descriptor '0'")
	}

	// set the default config
	defaultConfig, err := bpfModule.GetMap("default_config")
	if err != nil {
		log.Fatalf("failed to load default config map: %v", err)
	}

	// set up the ipv4 and ipv6 rules maps
	ip4_rules, err := bpfModule.GetMap("ip4_rules")
	if err != nil {
		log.Fatalf("failed to load ipv4 config map: %v", err)
	}
	ip6_rules, err := bpfModule.GetMap("ip6_rules")
	if err != nil {
		log.Fatalf("failed to load ipv6 config map: %v", err)
	}
	applyIPv4Rules(cfg, defaultConfig, ip4_rules)
	applyIPv6Rules(cfg, defaultConfig, ip6_rules)

	// use a Go channel to handle the incoming event messages
	passedPackets := make(chan []byte)
	passed, err := bpfModule.InitRingBuf("passed_packets", passedPackets)
	if err != nil {
		log.Fatalf("failed to initialize ring buffer: %v", err)
	}

	// start listening on the passed packets ringbuffer
	passed.Start()
	defer func() {
		passed.Stop()
		passed.Close()
	}()

	// start listening on the dropped packets ringbuffer
	droppedPackets := make(chan []byte)
	dropped, err := bpfModule.InitRingBuf("dropped_packets", droppedPackets)
	if err != nil {
		panic(err)
	}

	dropped.Start()
	defer func() {
		dropped.Stop()
		dropped.Close()
	}()

	// handle incoming event messages from both channels
	for {
		select {
		case evt := <-passedPackets:
			logXDPEvent(evt, bpfXdpActionXDP_PASS)
		case evt := <-droppedPackets:
			logXDPEvent(evt, bpfXdpActionXDP_DROP)
		case _ = <-stopper:
			return
		}
	}
}

// print message upon received event
func logXDPEvent(ipEvent []byte, bpfAction bpfXdpAction) {
	srcIpInfo, err := toBpfIpType(ipEvent)
	if err != nil {
		log.Printf("failed to convert source ip information: %v; skipping event", err)
	}
	var action string
	if bpfAction == bpfXdpActionXDP_PASS {
		action = "PASSED ON"
	} else {
		action = "DROPPED"
	}

	if srcIpInfo.Type == bpfIpTypeIPV4 {
		log.Printf("%s IPv4 packet from IP: %v", action, net.IP(srcIpInfo.Ip.Ipv6.In6U.U6Addr8[:4]))
	} else {
		log.Printf("%s IPv6 packet from IP: %v", action, net.IP(srcIpInfo.Ip.Ipv6.In6U.U6Addr8[:]))
	}
}

// convert byte slice to the specialized IP type
func toBpfIpType(evt []byte) (bpfSrcIpType, error) {
	var ipdata bpfSrcIpType
	err := binary.Read(bytes.NewBuffer(evt), binary.BigEndian, &ipdata)
	if err != nil {
		return bpfSrcIpType{}, err
	}
	return ipdata, nil
}

// parse and set IPv4 rules
func applyIPv4Rules(cfg *config, defaultConfig *libbpfgo.BPFMap, ip4Rules *libbpfgo.BPFMap) {
	if cfg.Rules.IPv4.Default != ALLOW && cfg.Rules.IPv4.Default != BLOCK {
		log.Fatalf("IPv4 default not set. This needs to be either 'allow' or 'block'.")
	}

	if cfg.Rules.IPv4.Default == BLOCK {
		log.Println("setting ipv4 default to false")
		err := defaultConfig.Update(toPtr(bpfIpTypeIPV4), toPtr(false))
		if err != nil {
			log.Fatalf("failed to put default value: %v", err)
		}
	} else {
		log.Println("Setting ipv4 default to true")
		err := defaultConfig.Update(toPtr(bpfIpTypeIPV4), toPtr(true))
		if err != nil {
			log.Fatalf("failed to put default value: %v", err)
		}
	}

	for _, v := range cfg.Rules.IPv4.Allow {
		ip := net.ParseIP(v)
		err := ip4Rules.Update(toPtr(ip.To4()), toPtr(true))
		if err != nil {
			log.Fatalf("failed to set up rule for ip %v: %v", ip, err)
		}
	}
	for _, v := range cfg.Rules.IPv4.Block {
		ip := net.ParseIP(v)
		err := ip4Rules.Update(toPtr(ip.To4()), toPtr(false))
		if err != nil {
			log.Fatalf("failed to set up rule for ip %v: %v", ip, err)
		}
	}
}

// parse and set IPv6 rules
func applyIPv6Rules(cfg *config, defaultConfig *libbpfgo.BPFMap, ip6Rules *libbpfgo.BPFMap) {
	if cfg.Rules.IPv6.Default != ALLOW && cfg.Rules.IPv6.Default != BLOCK {
		log.Fatalf("IPv6 default not set. This needs to be either 'allow' or 'block'.")
	}

	if cfg.Rules.IPv6.Default == "block" {
		log.Println("Setting ipv6 default to false")
		err := defaultConfig.Update(toPtr(bpfIpTypeIPV6), toPtr(false))
		if err != nil {
			log.Fatalf("failed to put default value: %v", err)
		}
	} else {
		log.Println("Setting ipv6 default to true")
		err := defaultConfig.Update(toPtr(bpfIpTypeIPV6), toPtr(true))
		if err != nil {
			log.Fatalf("failed to put default value: %v", err)
		}
	}

	for _, v := range cfg.Rules.IPv6.Allow {
		ip := net.ParseIP(v)
		err := ip6Rules.Update(toPtr(ip.To16()), toPtr(true))
		if err != nil {
			log.Fatalf("failed to set up rule for ip %v: %v", ip, err)
		}
	}
	for _, v := range cfg.Rules.IPv6.Block {
		ip := net.ParseIP(v)
		err := ip6Rules.Update(toPtr(ip.To16()), toPtr(false))
		if err != nil {
			log.Fatalf("failed to set up rule for ip %v: %v", ip, err)
		}
	}
}

// return a raw pointer to given value
func toPtr[E any](e E) unsafe.Pointer {
	return unsafe.Pointer(&e)
}
