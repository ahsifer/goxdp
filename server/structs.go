package main

import (
	"github.com/cilium/ebpf/link"
	"log"
	"net/netip"
	"time"
)

type BpfIpv4LpmKey struct {
	Prefixlen uint32
	Saddr     uint32
}

// the Application struct holds the shared data or the data that needs to be used frequently.
type Application struct {
	InfoLog          *log.Logger
	ErrorLog         *log.Logger
	BpfObjects       *bpfObjects
	Interfaces       *[]string
	LoadedInterfaces map[string]link.Link
	TimeoutList      map[BpfIpv4LpmKey]time.Time
	// Is_loaded        bool
}

// Structs used by xdpLoad and xdpUnload handlers
type load struct {
	Mode       *string `json:"mode"`
	Interfaces *string `json:"interfaces"`
	Src        *string `json:"src"`
	Action     *string `json:"action"`
	Timeout    *uint   `json:"timeout"`
}

// Structs for XDP status
type statusMapJson struct {
	Src          netip.Addr `json:"src"`
	Rx_packets   uint64     `json:"rx_count"`
	Size_packets uint64     `json:"bytes_dropped"`
}
type statusTimeoutOutput struct {
	Src       string `json:"src"`
	Timeout   string `json:"timeout"`
	Remaining int    `json:"remaining_time"`
}
type statusMapOutput struct {
	Interfaces []string              `json:"interfaces"`
	Blocked    []string              `json:"blocked"`
	Timeout    []statusTimeoutOutput `json:"timeout"`
	Status     []statusMapJson       `json:"stats"`
}
