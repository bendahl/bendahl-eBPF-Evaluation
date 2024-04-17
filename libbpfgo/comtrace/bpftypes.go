package main

// TCP event as received from the kernel -> generated using bpf2go
type bpfTcpEvent struct {
	Ip    uint64
	Pid   uint32
	Saddr struct {
		Family uint16
		Ip     struct{ Ipv6 [16]uint8 }
	}
	Daddr struct {
		Family uint16
		Ip     struct{ Ipv6 [16]uint8 }
	}
	Lport         uint16
	Dport         uint16
	Newstate      int32
	Oldstate      int32
	Comm          [16]int8
	_             [4]byte
	BytesReceived uint64
	BytesSent     uint64
	Tstamp        uint64
}
