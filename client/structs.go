package client

import (
	"net/http"
	"net/netip"
)

//Global structs

type ClientAPP struct {
	ServerURL    string
	TargetMaster bool
	HttpClient   *http.Client
}

type ErrorStatusMessage struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
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

// Struct for XDP Master status
type MasterStatus struct {
	PullCounter         uint           `json:"PULL_COUNTER"`      //store counter in the internal.json config file remain the same value during restarts
	PermBlockedIPsArray []string       `json:"PERMANENT_BLOCKED"` //stores the IP addresses and subnets that stored in blocked.list
	CliBlockedIPsArray  []BlockedCliIP `json:"CLI_BLOCKED"`       //stores the IP addresses and subnets that are blocked by the cli commands or restful API
}

type BlockedCliIP struct {
	Src     *string `json:"src"`
	Timeout *int    `json:"timeout,omitempty"` //pointer to integer to make it nullable for parsing process
	// Action  *string `json:"action,omitempty"`
}