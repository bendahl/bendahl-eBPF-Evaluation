package main

type bpfIn6Addr struct{ In6U struct{ U6Addr8 [16]uint8 } }

type bpfIpType uint32

const (
	bpfIpTypeIPV4 bpfIpType = 0
	bpfIpTypeIPV6 bpfIpType = 1
)

type bpfSrcIpType struct {
	Type bpfIpType
	Ip   struct{ Ipv6 bpfIn6Addr }
}

type bpfXdpAction uint32

const (
	bpfXdpActionXDP_ABORTED  bpfXdpAction = 0
	bpfXdpActionXDP_DROP     bpfXdpAction = 1
	bpfXdpActionXDP_PASS     bpfXdpAction = 2
	bpfXdpActionXDP_TX       bpfXdpAction = 3
	bpfXdpActionXDP_REDIRECT bpfXdpAction = 4
)
