/*
This program traces TCP connections and some of their metrics.
It is heavily inspired by the 'tcplife' program, created by Brendan Gregg and the BCC authors
See: https://www.brendangregg.com/blog/2016-11-30/linux-bcc-tcplife.html
See: https://github.com/iovisor/bcc/blob/master/tools/tcplife.py
*/
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf/rlimit"
)

// special compiler directive that triggers code generation when `go generate is invoked`
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type tcp_event -target amd64 bpf comtrace.bpf.c

// tcp states
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
	// program flags
	var duration *time.Duration = flag.Duration("d", 30*time.Second, "duration for which tcp event should be recorded - e.g. 30s or 1m")
	var outFileName *string = flag.String("o", "tcp_trace.log", "output file to write the recorded events to")
	var writeCaptions *bool = flag.Bool("c", false, "print captions")
	flag.Parse()

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

	// attach BPF program to tracepoint
	inetSockSetState, err := link.Tracepoint("sock", "inet_sock_set_state", objs.InetSockSetState, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer inetSockSetState.Close()

	// initialize ring buffer
	ip4ev, err := ringbuf.NewReader(objs.IpEvents)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer ip4ev.Close()

	// start recording events and wait for termination
	log.Println("Recording tcp events..")
	go recordEvents(ip4ev, outFileName, !*writeCaptions)
	waitForRecording(stopper, duration, ip4ev)
}

// waitForRecording waits for termination signal
func waitForRecording(stopper chan os.Signal, duration *time.Duration, ip4ev *ringbuf.Reader) {
	select {
	// termination signal received
	case <-stopper:
		break
	// time elapsed
	case <-time.After(*duration):
		break

	}

	// close ring buffer
	if err := ip4ev.Close(); err != nil {
		log.Fatalf("closing ringbuf reader: %s", err)
	}
}

// connection tuple that uniquely identifies each connection
type connection struct {
	saddr string
	daddr string
	sport uint16
	dport uint16
}

// connection meta data
type connectionMeta struct {
	pid           uint32
	comm          string
	bytesReceived uint64
	bytesSent     uint64
	startTs       uint64
	endTs         uint64
}

// recordEvents polls for tcp events and updates the connection cache
func recordEvents(ip4ev *ringbuf.Reader, outFileName *string, writeCaptions bool) {
	connections := make(map[connection]connectionMeta, 10)

	for {
		msg, err := ip4ev.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Saving report to disk...")
				writeReport(outFileName, connections, writeCaptions)
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		var tcpEvent bpfTcpEvent
		err = binary.Read(bytes.NewBuffer(msg.RawSample), binary.LittleEndian, &tcpEvent)
		if err != nil {
			log.Printf("Failed to retrieve write event: %v", err)
		}
		if tcpEvent.Lport == 0 {
			// ignore connections with local-port == 0
			continue
		}
		updateConnections(&tcpEvent, connections)
	}
}

// writeReport writes a formatted tcp connection report to the specified file
func writeReport(filename *string, connections map[connection]connectionMeta, writeCaptions bool) {
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

// updateConnections updates the connection cache
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
	// ensure that the startTs is only altered if this is a newly created connection
	// otherwise, we do not know how long this connection has been open for
	if meta.startTs == 0 && evt.Newstate < tcpFinWait1 {
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

// commToStr converts the given process name (byte array) to a string
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
