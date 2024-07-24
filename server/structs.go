package main

import (
	"github.com/cilium/ebpf/link"
	"log"
	"net/http"
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
	// LocalBlockedList map[BpfIpv4LpmKey]bool //holds the currently blocked IP address by the user directly not form the master
	// MasterBlockedList []string               //holds the IP addresses that are currently blocked by the master
	BlockedList []internalIP //store all the blocked IP addresses from both master and cli commands

	BlockedListPointers map[BpfIpv4LpmKey]int //used to check if IP address blocked by the CLi command to provide priority for local blocks and store the location of the blocked IP address in the BlockedList
	TimeoutList         map[BpfIpv4LpmKey]time.Time
	//master-slave related parameters
	PullCounter uint
	MasterURL   string
	MasterSSL   bool
	SlaveClient *http.Client

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

type internalIP struct {
	key        BpfIpv4LpmKey
	cliBlocked bool
}

//Slave worker structs

type MasterResponse struct {
	PullCounter      uint             `json:"PULL_COUNTER"`
	PermanentBlocked []string         `json:"PERMANENT_BLOCKED"`
	CLIBlocked       []MasterCLIBlock `json:"CLI_BLOCKED"`
}

type MasterCLIBlock struct {
	Src     string `json:"src"`
	Timeout int    `json:"timeout,omitempty"`
}
