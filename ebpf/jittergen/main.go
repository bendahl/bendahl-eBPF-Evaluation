/*
  This program is intended to simulate different network conditions, such as jitter, packet drop and packet reordering.
  Due to various issues regarding the resulting BPF binary, this program is not in a usable state.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	tc "github.com/florianl/go-tc"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
)

// configuration data structure
type config struct {
	OutIf  string `yaml:"outIf"`
	Action string `yaml:"action"`
	Match  struct {
		Percent  uint16 `yaml:"percent"`
		Protocol string `yaml:"protocol"`
		Port     uint16 `yaml:"port"`
	} `yaml:"match"`
	Jitter struct {
		MinDelayMs uint16 `yaml:"minDelayMs"`
		MaxDelayMs uint16 `yaml:"maxDelayMs"`
	} `yaml:"jitter"`
	Reorder struct {
		DelayMs uint16 `yaml:"delayMs"`
	} `yaml:"reorder"`
}

// special compiler directive that triggers code generation when `go generate is invoked`
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type setting -target amd64 bpf jittergen.bpf.c

const TC_EGRESS = 0xFFFFFFF3
const (
	ETH_P_IP uint16 = 0x0800
	IP_P_TCP uint16 = 0x06
	IP_P_UDP uint16 = 0x11
)

const ACTION_DROP = "drop"
const ACTION_JITTER = "jitter"
const ACTION_REORDER = "reorder"

// This is the main entrypoint to the program
func main() {
	// read and validate configuration file values
	cfg := readConfig()
	validateConfig(cfg)

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// load BPF objects from bytecode
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading bpf objects failed: %v", err)
	}
	defer func(objs *bpfObjects) {
		err := objs.Close()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to properly clean up bpf objects: %v", err)
		}
	}(&objs)

	// get network interface id by name
	devID, err := net.InterfaceByName(cfg.OutIf)
	if err != nil {
		log.Fatalf("could not get interface ID: %v\n", err)
	}

	// create a new handler object that will manage qdiscs and filters of the selected nic
	tcHandler := NewTCHandler(*devID)
	// add parent qdisc that can honors the skb->tstamp field for sending (egress side) -> in this case FQ (fair queue)
	err = tcHandler.AddQdisc(FQ, true)
	if err != nil {
		log.Fatalf("Failed ot add root qdisc: %v", err)
	}
	// add child qdisc of type clsact, allowing "direct action"
	err = tcHandler.AddQdisc(CLSACT, false)
	if err != nil {
		log.Fatalf("Failed to add qdisc: %v", err)
	}
	defer func(tcHandler *TCHandler) {
		err := tcHandler.Close()
		if err != nil {
			log.Fatalf("Failed to close tcHandler: %v", err)
		}
	}(&tcHandler)

	// attach BPF program to egress path of the nic
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		log.Fatalf("could not open rtnetlink socket: %v\n", err)
	}
	attachBpfProgram(objs, devID, tcnl)

	// populate settings BPF map
	applySettings(cfg, objs.Settings)

	// wait for termination signal
	<-stopper
}

/*
attachBpfProgram uses go-tc to attach the previously loaded bpf program to the appropriate qdisc.
*/
func attachBpfProgram(objs bpfObjects, devID *net.Interface, tcnl *tc.Tc) {
	fd := uint32(objs.TcJittergen.FD())
	flags := uint32(0x1)
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Parent:  TC_EGRESS, // interesting constants: https://pkg.go.dev/github.com/vishvananda/netlink#pkg-constants
			Info:    0x300,     // this value is also set by the tc utility when attaching the program using the command line (can be checked via strace)
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}
	if err := tcnl.Filter().Add(&filter); err != nil {
		log.Fatalf("could not attach filter for eBPF program: %v\n", err)
	}
}

/*
validateConfig validates the config file values in order to ensure consistency
*/
func validateConfig(cfg *config) {
	if strings.TrimSpace(cfg.OutIf) == "" {
		log.Fatalf("Outbound interface not defined.")
	}
	if cfg.Action != ACTION_DROP && cfg.Action != ACTION_JITTER && cfg.Action != ACTION_REORDER {
		log.Fatalf("Invalid configuration: Unknown action '%s'", cfg.Action)
	}
	if cfg.Match.Protocol != "tcp" && cfg.Match.Protocol != "udp" && cfg.Match.Protocol != "ip" {
		log.Fatalf("Invalid configuration: Unknown protocol '%s'", cfg.Match.Protocol)
	}
	if cfg.Match.Percent > 100 {
		log.Fatalf("Invalid percentage value given. Valid range: [0 - 100]")
	}
	if cfg.Jitter.MinDelayMs > 1000 || cfg.Jitter.MaxDelayMs > 1000 {
		log.Fatalf("Delay value is out of range. Valid range: [0 - 1000]")
	}
}

/*
apply settings sets the relevant parameters in the bpf map holding the application's configuration
*/
func applySettings(cfg *config, settings *ebpf.Map) {
	err := settings.Put(bpfSettingPERCENT, cfg.Match.Percent)
	if err != nil {
		log.Fatalf("Failed to initialize percentage: %v", err)
	}
	err = settings.Put(bpfSettingPORT, cfg.Match.Port)
	if err != nil {
		log.Fatalf("Failed to initialize port: %v", err)
	}

	switch cfg.Match.Protocol {
	case "tcp":
		err := settings.Put(bpfSettingPROTOCOL, IP_P_TCP)
		if err != nil {
			log.Fatalf("Failed to initialize protocol: %v", err)
		}
	case "udp":
		err := settings.Put(bpfSettingPROTOCOL, IP_P_UDP)
		if err != nil {
			log.Fatalf("Failed to initialize protocol: %v", err)
		}
	case "ip":
		err := settings.Put(bpfSettingPROTOCOL, ETH_P_IP)
		if err != nil {
			log.Fatalf("Failed to initialize protocol: %v", err)
		}
	default:
		log.Fatalf("Unsupported protocol: '%s'", cfg.Match.Protocol)
	}

	switch cfg.Action {
	case ACTION_JITTER:
		err = settings.Put(bpfSettingACTIONS, uint16(1))
		if err != nil {
			log.Fatalf("Failed to initialize actions: %v", err)
		}
		err = settings.Put(bpfSettingMIN_LAT, cfg.Jitter.MinDelayMs)
		if err != nil {
			log.Fatalf("Failed to initialize min delay: %v", err)
		}
		err = settings.Put(bpfSettingMAX_LAT, cfg.Jitter.MaxDelayMs)
		if err != nil {
			log.Fatalf("Failed to initialize max delay: %v", err)
		}
	case ACTION_DROP:
		err = settings.Put(bpfSettingACTIONS, uint16(2))
		if err != nil {
			log.Fatalf("Failed to initialize actions: %v", err)
		}
	case ACTION_REORDER:
		err = settings.Put(bpfSettingACTIONS, uint16(3))
		if err != nil {
			log.Fatalf("Failed to initialize actions: %v", err)
		}
		err = settings.Put(bpfSettingMIN_LAT, cfg.Reorder.DelayMs)
		if err != nil {
			log.Fatalf("Failed to initialize min delay: %v", err)
		}
		err = settings.Put(bpfSettingMAX_LAT, cfg.Reorder.DelayMs)
		if err != nil {
			log.Fatalf("Failed to initialize max delay: %v", err)
		}
	}
}

/*
readConfig reads and unmarshals the yaml configuration file
*/
func readConfig() *config {
	rawConfigBytes, err := os.ReadFile("config.yml")
	if err != nil {
		log.Fatalf("failed to read config.yml file: %v", err)
	}

	cfg := new(config)
	err = yaml.Unmarshal(rawConfigBytes, &cfg)
	if err != nil {
		log.Fatalf("failed to unmarshal configuration: %v", err)
	}
	return cfg
}
