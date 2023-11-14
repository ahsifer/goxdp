package main

import (
	"flag"
	"fmt"
	"github.com/dropbox/goebpf"
	"github.com/go-chi/chi/v5"
	"log"
	"net/http"
	"os"
)

type Application struct {
	MainProgram goebpf.Program
	// InterfaceProgrammes map[string]goebpf.Program
	IpAddressMap goebpf.Map
	StatusMap    goebpf.Map
}

var AppInstance Application

func main() {
	if len(os.Args) <= 1 {
		log.Fatal("Error: Bad input parameters:> \nUsage gxfilter <command> <options> \navailable commands are server, client\nconsider gxfilter <command> -h for more information")
	}

	//Handling server flags
	serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
	listenIP := serverFlags.String("ip", "127.0.0.1", "IP address will listen to")
	listenPort := serverFlags.String("port", "8090", "Port number will listen to")
	// Handling Client Flags
	clientFlags := flag.NewFlagSet("client", flag.ExitOnError)
	action := clientFlags.String("action", "", "Action to take. Available values are load,unload,drop,allow")
	_ = action
	ip := clientFlags.String("ip", "", "IP address")
	_ = ip
	subnet := clientFlags.String("subnet", "", "Network Subnet")
	_ = subnet
	mode := clientFlags.String("mode", "", "The mode that XDP program will work. Available values are skb, native, and hw")
	_ = mode
	timeout := clientFlags.String("timeout", "", "How long the IP address or the subnet will be blocked")
	_ = timeout
	interfaceName := clientFlags.String("interface", "", "Interface name that XDP code will be attached to")
	_ = interfaceName

	// Start server section
	if os.Args[1] == "server" {
		// ip := flag.String("ip", "127.0.0.1", "IP address will listen to (default 127.0.0.1)")
		// port := flag.String("port", "8090", "Port number will listen to (default 8090)")
		//Parse input flags
		serverFlags.Parse(os.Args[2:])

		bpf := goebpf.NewDefaultEbpfSystem()
		// bpf.
		err := bpf.LoadElf("/etc/gxfilter/xdp.o")
		if err != nil {
			log.Fatalf("Error: /etc/gxfilter/xdp.o file not found")
		}
		ipAddresses := bpf.GetMapByName("IP_ADDRESSES")
		if ipAddresses == nil {
			log.Fatalf("Error: eBPF map 'IP_ADDRESSES' not found\n")
		}

		statusMap := bpf.GetMapByName("STATUS")
		if ipAddresses == nil {
			log.Fatalf("Error: eBPF map 'STATUS' not found\n")
		}

		xdp := bpf.GetProgramByName("firewall")
		if xdp == nil {
			log.Fatalln("Error: Program 'firewall' not found in Program")
		}
		err = xdp.Load()
		if err != nil {
			log.Fatalln("Error: Unable to load the XDP program into the kernel -> detailed error: ", err)
		}
		AppInstance.MainProgram = xdp
		AppInstance.IpAddressMap = ipAddresses
		AppInstance.StatusMap = statusMap
		// AppInstance.InterfaceProgrammes = make(map[string]goebpf.Program)

		// Create new map

		r := chi.NewRouter()

		r.Post("/load", xdpLoad)
		r.Post("/unload/{interface}", xdpUnload)
		log.Print(*listenIP, " ", *listenPort)
		err = http.ListenAndServe(fmt.Sprintf("%s:%s", *listenIP, *listenPort), r)
		if err != nil {
			log.Fatal("Error:Unable to start the server -> error details: ", err)
		}
		log.Print(fmt.Sprintf("INFO: Filter is started and listening on %s:%s ", *listenIP, *listenPort))
		//Start client section

	} else if os.Args[1] == "client" {
		clientFlags.Parse(os.Args[2:])
		// log.Println(os.Args)
		// flag.PrintDefaults()
	} else {
		log.Panic("Error Bad input parameters:> Usage gxfilter <command> \navailable commands are server, client\n consider gxfilter <command> -h for more information")
	}

}
