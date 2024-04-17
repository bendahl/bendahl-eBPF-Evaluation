/*
This program traces TCP connections and some of their metrics.
It is heavily inspired by the 'tcplife' program, created by Brendan Gregg and the BCC authors
See: https://www.brendangregg.com/blog/2016-11-30/linux-bcc-tcplife.html
See: https://github.com/iovisor/bcc/blob/master/tools/tcplife.py
*/
package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
)

// special compiler directive to tell the go tool to embed the given object file in the resulting binary
//
//go:embed comtrace.bpf.o
var bpfobject []byte

// TCP states
const (
	tcpEstablished int32 = iota + 1
	tcpSynSent
	tcpSynRecv
	tcpFinWait1
	tcpFinWait2
	tcpTimeWait
	tcpClose
	tcpCloseWait
	tcpLastAck
	tcpListen
	tcpClosing
	tcpNewSynRecv
)

// This is the main entrypoint to the program
func main() {
	// command line parameters
	var duration *time.Duration = flag.Duration("d", 30*time.Second, "duration for which tcp event shoud be recorded - e.g. 30s or 1m")
	var outFileName *string = flag.String("o", "tcp_trace.log", "output file to write the recorded events to")
	var writeCaptions *bool = flag.Bool("c", false, "print captions")
	flag.Parse()

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Load pre-compiled programs and maps into the kernel.
	bpfModule, err := libbpfgo.NewModuleFromBuffer(bpfobject, "packetfilter.bpf.o")
	if err != nil {
		log.Fatalf("failed to load bpf module from file: %v", err)
	}
	defer bpfModule.Close()

	// load BPF ojbects
	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatalf("failed to load bpf module: %v", err)
	}

	// get and attach BPF program
	bpfProg, err := bpfModule.GetProgram("inet_sock_set_state")
	if err != nil {
		log.Fatalf("failed to get bpf program: %v", err)
	}
	bpflink, err := bpfProg.AttachTracepoint("sock", "inet_sock_set_state")
	if err != nil {
		log.Fatalf("failed to attach trace program: %v", err)
	}
	if bpflink.FileDescriptor() == 0 {
		log.Fatalf("invalid bpflink file descriptor '0'")
	}

	// create a channel to listen to events
	events := make(chan []byte)
	buffer, err := bpfModule.InitRingBuf("ip_events", events)
	if err != nil {
		panic(err)
	}

	// start listening for events
	buffer.Start()
	defer func() {
		buffer.Stop()
		buffer.Close()
	}()
	log.Println("Recording tcp events..")
	// process events as they come in
	processEvents(stopper, duration, events, outFileName, !*writeCaptions)
}

// processEvents listens for incoming TCP events and collects event data until the specified time is up or a termination signal is received
func processEvents(stopper chan os.Signal, duration *time.Duration, ip4ev chan []byte, outFileName *string, writeCaptions bool) {
	connections := make(map[connection]connectionMeta, 10)

	// run forever
	for {
		// process events
		select {
		// event received -> process and add to list of events
		case event := <-ip4ev:
			var tcpEvent bpfTcpEvent
			err := binary.Read(bytes.NewBuffer(event), binary.LittleEndian, &tcpEvent)
			if err != nil {
				log.Printf("failed to retrieve write event: %v", err)
			}
			if tcpEvent.Lport == 0 {
				// ignore connections with local-port == 0
				continue
			}
			updateConnections(&tcpEvent, connections)
		// signal received -> exit
		case <-stopper:
			writeReport(outFileName, connections, writeCaptions)
			return
		// time is up -> exit
		case <-time.After(*duration):
			writeReport(outFileName, connections, writeCaptions)
			return
		}
	}

}

// connectin tuple, represented by source and target ip and port
type connection struct {
	saddr string
	daddr string
	sport uint16
	dport uint16
}

// connection meta data that is unique for each connection
type connectionMeta struct {
	pid           uint32
	comm          string
	bytesReceived uint64
	bytesSent     uint64
	startTs       uint64
	endTs         uint64
}

// writeReport writes a final report to the specified file
func writeReport(filename *string, connections map[connection]connectionMeta, writeCaptions bool) {
	log.Println("Saving report to disk...")
	outfile, err := os.OpenFile(*filename, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		log.Printf("[ERROR] Failed to write report file: %v", err)
	}
	w := tabwriter.NewWriter(outfile, 2, 2, 1, ' ', 0)

	if writeCaptions {
		fmt.Fprintln(w, "PID\tCOMM\tLOCAL_IP\tLOCAL_PORT\tREMOTE_IP\tREMOTE_PORT\tRX_BYTES\tTX_BYTES\t\tMS")
		fmt.Fprintln(w, "---\t----\t--------\t----------\t---------\t-----------\t--------\t--------\t\t--")
	}
	for con, meta := range connections {
		var millis uint64 = 0
		if meta.endTs > 0 && meta.startTs > 0 {
			millis = (meta.endTs - meta.startTs) / (1000 * 1000)
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\t%d\t%d\t%d\t\t%d\n",
			meta.pid,
			meta.comm,
			con.saddr,
			con.sport,
			con.daddr,
			con.dport,
			meta.bytesReceived,
			meta.bytesSent,
			millis)
	}
	w.Flush()
}

// updateConnections updates the internal connection cache
func updateConnections(evt *bpfTcpEvent, connections map[connection]connectionMeta) {
	con := connection{
		saddr: toIpStr(evt.Saddr.Ip.Ipv6, evt.Saddr.Family),
		daddr: toIpStr(evt.Daddr.Ip.Ipv6, evt.Daddr.Family),
		sport: evt.Lport,
		dport: evt.Dport,
	}
	meta, exists := connections[con]
	if !exists {
		meta = connectionMeta{
			comm:          "",
			bytesReceived: evt.BytesReceived,
			bytesSent:     evt.BytesSent,
			startTs:       0,
			endTs:         0,
		}
	}

	// note that we might have missed the first events, so the first event received
	// will be used as a referencce point
	if meta.startTs == 0 {
		meta.startTs = evt.Tstamp
	}

	// similarly, we cannot tell whether a connection will outlive the current trace
	// therefore, the last seen timestamp is used as an end timestamp
	meta.endTs = evt.Tstamp
	meta.bytesReceived = evt.BytesReceived
	meta.bytesSent = evt.BytesSent
	if evt.Newstate == tcpSynSent || evt.Newstate == tcpFinWait1 || evt.Newstate == tcpLastAck {
		meta.pid = evt.Pid
		meta.comm = commToStr(evt.Comm)
	}
	connections[con] = meta
}

// toIpStr converts a byte array to an IP string
func toIpStr(addr [16]uint8, family uint16) string {
	if family == unix.AF_INET {
		return net.IPv4(addr[0], addr[1], addr[2], addr[3]).String()
	}
	return net.IP(addr[:]).String()
}

// commToStr formats the given byte array to a valid process name
func commToStr(bs [16]int8) string {
	b := make([]rune, 16)
	for i, v := range bs {
		if v == 0 {
			b[i] = ' '
		} else {
			b[i] = rune(v)
		}
	}
	return string(b)
}
