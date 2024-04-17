/*
This program implements a simple XDP-based packet filter that allows/blocks ip packets from predefined source addresses.
The configuration is done via a yaml-file.
Filtering rules are stored in BPF maps, so that the BPF program that performs the actual packet filtering can read and apply them.
*/
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
)

// special compiler directive that triggers code generation when `go generate is invoked`
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -type xdp_action -type ip_type -type in6_addr -type src_ip_type -target amd64 bpf paketfilter.bpf.c

const ALLOW = "allow"
const BLOCK = "block"

// configuration data structure
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

type xdpEvent struct {
	action    bpfXdpAction
	srcIpInfo bpfSrcIpType
}

// This is the main entrypoint to the program
func main() {
	// read configuration file
	rawConfigBytes, err := ioutil.ReadFile("config.yml")
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
	listenInterface, err := net.InterfaceByName(cfg.Rules.Interface)
	if err != nil {
		log.Fatalf("unkonwn interface: %v", listenInterface)
	}
	log.Printf("Using interface %v\n", listenInterface.Name)

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
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	// attach XDP program to specified nic
	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
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

	// apply rules set in block-/allow-lists
	applyIPv4Rules(cfg, objs)
	applyIPv6Rules(cfg, objs)

	// initialize ring buffer to listen for allowed packet events
	passedPackets, err := ringbuf.NewReader(objs.PassedPackets)
	if err != nil {
		log.Fatalf("failed to open ringbuffer reader for passed packets: %s", err)
	}
	defer func(passedPackets *ringbuf.Reader) {
		log.Println("Closing ringbuffer for passed packets")
		err := passedPackets.Close()
		if err != nil {
			log.Fatalf("failed to close ringbuffer for passed packets: %v", err)
		}
	}(passedPackets)

	// initialize ring buffer to listen for dropped packet events
	droppedPackets, err := ringbuf.NewReader(objs.DroppedPackets)
	if err != nil {
		log.Fatalf("failed to open ringbuffer reader for passed packets: %s", err)
	}
	defer func(droppedPackets *ringbuf.Reader) {
		log.Println("Closing ringbuffer for passed packets")
		err := droppedPackets.Close()
		if err != nil {
			log.Fatalf("failed to close ringbuffer for passed packets: %v", err)
		}
	}(droppedPackets)

	log.Println("Paketfilter successfully attached. Press CTRL+C to disable.")

	// create channel to process events and start listening on ring buffers
	xdpEvents := make(chan xdpEvent, 1024)
	go listenPassedEvents(passedPackets, xdpEvents)
	go listenDroppedEvents(droppedPackets, xdpEvents)

	// run forever
	for {
		select {
		// process XDP packet event in ring buffer
		case evt := <-xdpEvents:
			logXDPEvent(evt)
		// process termination signal -> end loop
		case _ = <-stopper:
			return
		}
	}
}

// listenPassedEvents continuously listens for incoming allowed packet events
func listenPassedEvents(passedPackets *ringbuf.Reader, evtChannel chan xdpEvent) {
	for {
		msg, err := passedPackets.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Ringbuffer for passed packets is closed")
				return
			}
			log.Printf("Reading from reader: %s", err)
			continue
		}

		publishEvent(err, msg, evtChannel, bpfXdpActionXDP_PASS)
	}
}

// listenDroppedEvents continuously listens for incoming dropped packet events
func listenDroppedEvents(droppedPackets *ringbuf.Reader, evtChannel chan xdpEvent) {
	for {
		msg, err := droppedPackets.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Ringbuffer for dropped packets is closed")
				return
			}
			log.Printf("Reading from reader: %s", err)
			continue
		}

		publishEvent(err, msg, evtChannel, bpfXdpActionXDP_DROP)
	}
}

// publishEvent pushes events to the event channel
func publishEvent(err error, msg ringbuf.Record, evtChannel chan xdpEvent, action bpfXdpAction) {
	var ipdata bpfSrcIpType
	err = binary.Read(bytes.NewBuffer(msg.RawSample), binary.BigEndian, &ipdata)
	if err != nil {
		log.Printf("failed to retrieve event: %v", err)
	}

	evt := xdpEvent{
		action:    action,
		srcIpInfo: ipdata,
	}
	evtChannel <- evt
}

// logXDPEvent prints a formatted event message
func logXDPEvent(event xdpEvent) {
	var action string
	if event.action == bpfXdpActionXDP_PASS {
		action = "PASSED ON"
	} else {
		action = "DROPPED"
	}

	if event.srcIpInfo.Type == bpfIpTypeIPV4 {
		log.Printf("%s IPv4 packet from IP: %v", action, net.IP(event.srcIpInfo.Ip.Ipv6.In6U.U6Addr8[:4]))
	} else {
		log.Printf("%s IPv6 packet from IP: %v", action, net.IP(event.srcIpInfo.Ip.Ipv6.In6U.U6Addr8[:]))
	}
}

// applyIPv4Rules applies the IPv4-specific filter rules
func applyIPv4Rules(cfg *config, objs bpfObjects) {
	if cfg.Rules.IPv4.Default != ALLOW && cfg.Rules.IPv4.Default != BLOCK {
		log.Fatalf("IPv4 default not set. This needs to be either 'allow' or 'block'.")
	}

	if cfg.Rules.IPv4.Default == BLOCK {
		log.Println("setting ipv4 default to false")
		err := objs.DefaultConfig.Put(bpfIpTypeIPV4, false)
		if err != nil {
			log.Fatalf("failed to put default value: %v", err)
		}
	} else {
		log.Println("Setting ipv4 default to true")
		err := objs.DefaultConfig.Put(bpfIpTypeIPV4, true)
		if err != nil {
			log.Fatalf("failed to put default value: %v", err)
		}
	}

	for _, v := range cfg.Rules.IPv4.Allow {
		ip := net.ParseIP(v)
		err := objs.Ip4Rules.Put(ip.To4(), true)
		if err != nil {
			log.Fatalf("failed to set up rule for ip %v: %v", ip, err)
		}
	}
	for _, v := range cfg.Rules.IPv4.Block {
		ip := net.ParseIP(v)
		err := objs.Ip4Rules.Put(ip.To4(), false)
		if err != nil {
			log.Fatalf("failed to set up rule for ip %v: %v", ip, err)
		}
	}
}

// applyIPv4Rules applies the IPv6-specific filter rules
func applyIPv6Rules(cfg *config, objs bpfObjects) {
	if cfg.Rules.IPv6.Default != ALLOW && cfg.Rules.IPv6.Default != BLOCK {
		log.Fatalf("IPv6 default not set. This needs to be either 'allow' or 'block'.")
	}

	if cfg.Rules.IPv6.Default == "block" {
		log.Println("Setting ipv6 default to false")
		err := objs.DefaultConfig.Put(bpfIpTypeIPV6, false)
		if err != nil {
			log.Fatalf("failed to put default value: %v", err)
		}
	} else {
		log.Println("Setting ipv6 default to true")
		err := objs.DefaultConfig.Put(bpfIpTypeIPV6, true)
		if err != nil {
			log.Fatalf("failed to put default value: %v", err)
		}
	}

	for _, v := range cfg.Rules.IPv6.Allow {
		ip := net.ParseIP(v)
		err := objs.Ip6Rules.Put(ip.To16(), true)
		if err != nil {
			log.Fatalf("failed to set up rule for ip %v: %v", ip, err)
		}
	}
	for _, v := range cfg.Rules.IPv6.Block {
		ip := net.ParseIP(v)
		err := objs.Ip6Rules.Put(ip.To16(), false)
		if err != nil {
			log.Fatalf("failed to set up rule for ip %v: %v", ip, err)
		}
	}
}
