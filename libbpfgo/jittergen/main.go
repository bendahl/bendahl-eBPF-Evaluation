/*
This program is intended to simulate different network conditions, such as jitter, packet drop and packet reordering.
Due to various issues regarding the resulting BPF binary, this program is not in a usable state.
*/
package main

import (
	_ "embed"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"

	"gopkg.in/yaml.v3"
)

// special compiler directive that tells the go tool to embed the given object file into the resulting binary
//
//go:embed jittergen.bpf.o
var bpfobject []byte

// configuration file data structure
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

const TC_EGRESS = 0xFFFFFFF3
const (
	ETH_P_IP uint16 = 0x0800
	IP_P_TCP uint16 = 0x06
	IP_P_UDP uint16 = 0x11
)

const ACTION_DROP = "drop"
const ACTION_JITTER = "jitter"
const ACTION_REORDER = "reorder"

// This is the main entrypoint of the program
func main() {
	// parse the config file
	cfg := readConfig()
	validateConfig(cfg)

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// retrieve the network interface id of the given nic
	devID, err := net.InterfaceByName(cfg.OutIf)
	if err != nil {
		log.Fatalf("could not get interface ID: %v\n", err)
	}

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

	// create a new TCHandler that will handle qdisc management
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
	hook := bpfModule.TcHookInit()
	err = hook.SetInterfaceByName(cfg.OutIf)
	if err != nil {
		log.Fatalf("failed to set tc hook on interface lo: %v", err)
	}

	// use the egress path of the nic
	hook.SetAttachPoint(libbpfgo.BPFTcEgress)
	err = hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			log.Fatalf("failed to create tc hook: %v", err)
		}
	}
	defer hook.Destroy()

	// get and load the BPF program
	tcProg, err := bpfModule.GetProgram("tc_jittergen")
	if tcProg == nil {
		log.Fatal(err)
	}

	// attach the program to the egress path of the nic
	var tcOpts libbpfgo.TcOpts
	tcOpts.ProgFd = tcProg.FileDescriptor()
	err = hook.Attach(&tcOpts)
	if err != nil {
		log.Fatal(err)
	}

	// load settings BPF map
	settings, err := bpfModule.GetMap("settings")
	if err != nil {
		log.Fatalf("failed to load settings map: %v", err)
	}

	// populate settings map
	applySettings(cfg, settings)

	<-stopper
}

// validateConfig validates the config file values in order to ensure consistency
func validateConfig(cfg *config) {
	if strings.TrimSpace(cfg.OutIf) == "" {
		log.Fatalf("Outbound interface not defined.")
	}
	if cfg.Action != ACTION_DROP && cfg.Action != ACTION_JITTER && cfg.Action != ACTION_REORDER {
		log.Fatalf("Invalid configuration: Unkown action '%s'", cfg.Action)
	}
	if cfg.Match.Protocol != "tcp" && cfg.Match.Protocol != "udp" && cfg.Match.Protocol != "ip" {
		log.Fatalf("Invalid configuration: Unkown protocol '%s'", cfg.Match.Protocol)
	}
	if cfg.Match.Percent > 100 {
		log.Fatalf("Invalid percentage value given. Valid range: [0 - 100]")
	}
	if cfg.Jitter.MinDelayMs > 1000 || cfg.Jitter.MaxDelayMs > 1000 {
		log.Fatalf("Delay value is out of range. Valid range: [0 - 1000]")
	}
}

// apply settings sets the relevant parameters in the bpf map holding the application's configuration
func applySettings(cfg *config, settings *libbpfgo.BPFMap) {
	err := settings.Update(toPtr(bpfSettingPERCENT), toPtr(cfg.Match.Percent))
	if err != nil {
		log.Fatalf("Failed to initialize percentage: %v", err)
	}
	err = settings.Update(toPtr(bpfSettingPORT), toPtr(cfg.Match.Port))
	if err != nil {
		log.Fatalf("Failed to initialize port: %v", err)
	}

	switch cfg.Match.Protocol {
	case "tcp":
		err := settings.Update(toPtr(bpfSettingPROTOCOL), toPtr(IP_P_TCP))
		if err != nil {
			log.Fatalf("Failed to initialize protocol: %v", err)
		}
	case "udp":
		err := settings.Update(toPtr(bpfSettingPROTOCOL), toPtr(IP_P_UDP))
		if err != nil {
			log.Fatalf("Failed to initialize protocol: %v", err)
		}
	case "ip":
		err := settings.Update(toPtr(bpfSettingPROTOCOL), toPtr(ETH_P_IP))
		if err != nil {
			log.Fatalf("Failed to initialize protocol: %v", err)
		}
	default:
		log.Fatalf("Unsupported protocol: '%s'", cfg.Match.Protocol)
	}

	switch cfg.Action {
	case ACTION_JITTER:
		err = settings.Update(toPtr(bpfSettingACTIONS), toPtr(uint16(1)))
		if err != nil {
			log.Fatalf("Failed to initialize actions: %v", err)
		}
		err = settings.Update(toPtr(bpfSettingMIN_LAT), toPtr(cfg.Jitter.MinDelayMs))
		if err != nil {
			log.Fatalf("Failed to initialize min delay: %v", err)
		}
		err = settings.Update(toPtr(bpfSettingMAX_LAT), toPtr(cfg.Jitter.MaxDelayMs))
		if err != nil {
			log.Fatalf("Failed to initialize max delay: %v", err)
		}
	case ACTION_DROP:
		err = settings.Update(toPtr(bpfSettingACTIONS), toPtr(uint16(2)))
		if err != nil {
			log.Fatalf("Failed to initialize actions: %v", err)
		}
	case ACTION_REORDER:
		err = settings.Update(toPtr(bpfSettingACTIONS), toPtr(uint16(3)))
		if err != nil {
			log.Fatalf("Failed to initialize actions: %v", err)
		}
		err = settings.Update(toPtr(bpfSettingMIN_LAT), toPtr(cfg.Reorder.DelayMs))
		if err != nil {
			log.Fatalf("Failed to initialize min delay: %v", err)
		}
		err = settings.Update(toPtr(bpfSettingMAX_LAT), toPtr(cfg.Reorder.DelayMs))
		if err != nil {
			log.Fatalf("Failed to initialize max delay: %v", err)
		}
	}
}

// readConfig reads and unmarshals the yaml configuration file
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

// get raw pointer for given value
func toPtr[E any](e E) unsafe.Pointer {
	return unsafe.Pointer(&e)
}
