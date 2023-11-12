package main

import (
	"fmt"
	"github.com/dropbox/goebpf"
	"github.com/go-chi/chi/v5"
	"log"
	"net/http"
)

type Application struct {
	Program      goebpf.Program
	IpAddressMap goebpf.Map
	StatusMap    goebpf.Map
}

var AppInstance Application

func main() {
	// Load XDP Into App
	bpf := goebpf.NewDefaultEbpfSystem()
	// bpf.
	err := bpf.LoadElf("/etc/goxdp/xdp.o")
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	ipAddresses := bpf.GetMapByName("IP_ADDRESSES")
	if ipAddresses == nil {
		log.Fatalf("eBPF map 'IP_ADDRESSES' not found\n")
	}

	statusMap := bpf.GetMapByName("STATUS")
	if ipAddresses == nil {
		log.Fatalf("eBPF map 'STATUS' not found\n")
	}
	_ = statusMap

	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		log.Fatalln("Program 'firewall' not found in Program")
	}
	err = xdp.Load()
	if err != nil {
		fmt.Printf("xdp.Attach(): %v", err)
	}
	AppInstance.Program = xdp
	AppInstance.IpAddressMap = ipAddresses
	AppInstance.StatusMap = statusMap

	r := chi.NewRouter()

	r.Post("/load", xdpLoad)
	// r.Get("/unload", GetItem)

	http.ListenAndServe(":8080", r)
}
