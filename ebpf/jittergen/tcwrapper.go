package main

import (
	"io"
	"net"
	"os/exec"
)

type direction string

type qdiscType string

const (
	FQ     qdiscType = "fq"
	CLSACT qdiscType = "clsact"
)

// TC wraps basic functionality required to interact with the Linux Traffic Control subsystem.
// Under the hood the tc tool is used to execute the required commands. This tool is usually part of the iproute2 suite.
// Also note that root privileges are required to modify qdiscs and filters.
type TC interface {

	// AddQdisc will add a new qdisc to an existing interface.
	// If 'isRoot' is set to true, the new qdisc will replace the currently assigned root qdisc.
	// Note that at this point only the "fq" and "clsact" qdiscs are supported.
	AddQdisc(qType qdiscType, isRoot bool) error

	// AttachFilter attaches a filter to an interface.
	// The 'objectFilePath' parameter should point to a prebuilt bpf object file.
	// The 'section' parameter is needed to identify the elf section that contains the actual program code.
	AttachFilter(dir direction, objectFilePath string, section string) error

	io.Closer
}

type TCHandler struct {
	nic     net.Interface
	qdiscs  []qdisc
	filters []filter
}

type qdisc struct {
	qType  qdiscType
	isRoot bool
}

type filter struct {
	dir            direction
	objectFilePath string
	section        string
}

// NewTCHandler returns a new instance of a TCHandler that handles the attachment/detachment of qdiscs and filters for a
// given network interface.
func NewTCHandler(nic net.Interface) TCHandler {
	handler := TCHandler{
		nic:     nic,
		qdiscs:  make([]qdisc, 0, 3),
		filters: make([]filter, 0, 3),
	}
	return handler
}

func (T *TCHandler) AddQdisc(qType qdiscType, isRoot bool) error {
	var cmd *exec.Cmd
	if isRoot {
		cmd = exec.Command("tc", "qdisc", "add", "dev", T.nic.Name, "root", string(qType))
	} else {
		cmd = exec.Command("tc", "qdisc", "add", "dev", T.nic.Name, string(qType))
	}
	if err := cmd.Run(); err != nil {
		return err
	}

	T.qdiscs = append(T.qdiscs, qdisc{
		qType:  qType,
		isRoot: isRoot,
	})

	return nil
}

func (T *TCHandler) AttachFilter(dir direction, objectFilePath string, section string) error {
	cmd := exec.Command("tc", "filter", "add", "dev", T.nic.Name, string(dir), "bpf", "da", "obj", objectFilePath, "sec", section)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

// Close will delete all currently attached filters and qdiscs from a given interface.
// As a result the default state of the interface will be restored.
func (T *TCHandler) Close() error {
	if T.filters != nil {
		for _, f := range T.filters {
			cmd := exec.Command("tc", "filter", "delete", "dev", T.nic.Name, string(f.dir))
			err := cmd.Run()
			if err != nil {
				return err
			}
		}
	}

	if T.qdiscs != nil {
		var cmd *exec.Cmd
		for _, q := range T.qdiscs {
			if q.isRoot {
				cmd = exec.Command("tc", "qdisc", "delete", "dev", T.nic.Name, "root")
			} else {
				cmd = exec.Command("tc", "qdisc", "delete", "dev", T.nic.Name, string(q.qType))
			}
			err := cmd.Run()
			if err != nil {
				return err
			}
		}
	}
	return nil
}
