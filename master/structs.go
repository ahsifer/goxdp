package master

import (
	"log"
)

type MasterAPP struct {
	InfoLog               *log.Logger
	ErrorLog              *log.Logger
	ServerIP              string
	ServerPort            string
	PullCounter           uint
	SlavesConfigFile      string
	AuthConfigFile        string
	AuthUsers             map[string]string
	PermBlockedConfigFile string
	PermBlockedIPsArray   []string
	PermBlockedIPsHashMap map[string]int
	InternalConfPath      string
	CliBlockedIPsArray    []BlockedCliIP
	CliBlockedIPsHashMap  map[string]int
	//Stores slave nodes configuration
	Slaves        SlaveNodes
	SlavesHashMap map[string]SingleSlaveConfig
	//Users map used to store map[token]username to check if user exists and authorized
	AutoPropagate bool
}

// Slaves file json struct parsing
type SingleSlaveConfig struct {
	Name  string `json:"NAME"`
	Host  string `json:"HOST"`
	Port  string `json:"PORT"`
	Token string `json:"TOKEN"`
}
type SlaveNodes []SingleSlaveConfig

// Authentication JSON struct parsing
type SingleUserConfig struct {
	Name  string `json:"USERNAME"`
	Token string `json:"TOKEN"`
}
type AuthUsers []SingleUserConfig

// internal.json file structs
type InternalConfigJson struct {
	PullCounter         uint           `json:"PULL_COUNTER"`                //store counter in the internal.json config file remain the same value during restarts
	PermBlockedIPsArray []string       `json:"PERMANENT_BLOCKED,omitempty"` //stores the IP addresses and subnets that stored in blocked.list
	CliBlockedIPsArray  []BlockedCliIP `json:"CLI_BLOCKED"`                 //stores the IP addresses and subnets that are blocked by the cli commands or restful API
}

type BlockedCliIP struct {
	Src     *string `json:"src"`
	Timeout *int    `json:"timeout,omitempty"` //pointer to integer to make it nullable for parsing process
	Action  *string `json:"action,omitempty"`
}

//Struct only for the pull counter json parser

type PullCounterRes struct {
	PullCounter uint `json:"PULL_COUNTER"`
}
