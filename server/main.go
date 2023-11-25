package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/ahsifer/goxdp/client"
	"github.com/cilium/ebpf/link"

	"log"
	"net/http"
	"os"
	// "strings"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ../source/xdp.c -- -I../headers

// the blockedTimeout map used to store the blocked subnets that includes timeout

func main() {
	defMessage := "Error: Bad input parameters:> \nUsage:\n \tgoxdp <command> <options> \navailable commands are:\n\tserver \tstart XDP HTTP server for handling users requests\n\tclient\tinteract with the XDP server\nFlags:\n\t-h,--h\tfor help"
	if len(os.Args) <= 1 {
		log.Fatal(defMessage)
	}

	//Handling server flags
	serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
	listenIP := serverFlags.String("ip", "127.0.0.1", "IP address will listen to")
	listenPort := serverFlags.String("port", "8090", "Port number will listen to")
	timeoutWorkerInterval := serverFlags.Int("timeoutinterval", 30, "The timeout of the worker thread to check if subnet or IP address timeout is finished")
	// Handling Client Flags
	clientFlags := flag.NewFlagSet("client", flag.ExitOnError)
	actionClient := clientFlags.String("action", "", "Available values are load,unload,block, allow, status")
	interfacesClient := clientFlags.String("interfaces", "", "Interfaces names that the XDP programme will be loaded to (Example 'eth0,eth1')")
	modeClient := clientFlags.String("mode", "", "The mode that XDP programme will be loaded (available values are nv,skb, and hw)")

	srcClient := clientFlags.String("src", "", "src IP address or subnet that will be blocked or allowed")
	_ = srcClient

	timeoutClient := clientFlags.String("timeout", "", "How long the IP address or the subnet will be blocked in seconds")
	_ = timeoutClient

	serverIPClient := clientFlags.String("ip", "127.0.0.1", "How long the IP address or the subnet will be blocked in seconds")
	_ = serverIPClient

	serverPortClient := clientFlags.String("port", "8090", "How long the IP address or the subnet will be blocked in seconds")
	_ = serverPortClient

	if os.Args[1] == "server" {
		serverFlags.Parse(os.Args[2:])
		//Instance of the application struct
		app := Application{
			InfoLog:          log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime),
			ErrorLog:         log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile),
			LoadedInterfaces: map[string]link.Link{},
			TimeoutList:      map[BpfIpv4LpmKey]time.Time{},
			Is_loaded:        false,
		}
		//check if user entered correct timeout interval for the timeout worker
		if *timeoutWorkerInterval < 5 {
			app.ErrorLog.Fatal("TimeoutWorkerInterval should 5 or greater")
		}
		//start timeout worker
		go app.timeoutWorker(*timeoutWorkerInterval)
		//create object of the xdp firewall
		objs := bpfObjects{}
		if err := loadBpfObjects(&objs, nil); err != nil {
			app.ErrorLog.Fatalf("cannot load objects: %s", err)
		}
		app.BpfObjects = &objs

		srv := &http.Server{
			Addr:     fmt.Sprintf("%s:%s", *listenIP, *listenPort),
			ErrorLog: app.ErrorLog,
			Handler:  app.newRouter(),
		}
		app.InfoLog.Printf("Starting server on IP: %s, Port: %s", *listenIP, *listenPort)
		err := srv.ListenAndServe()
		if err != nil {
			app.ErrorLog.Fatal(err)
		}
	} else if os.Args[1] == "client" {
		//Begin Client Section
		clientFlags.Parse(os.Args[2:])
		//Create new clientApp struct
		clientApp := client.ClientAPP{
			ServerIP:   *serverIPClient,
			ServerPort: *serverPortClient,
		}

		if *actionClient == "" {
			log.Print("Action flag cannot be empty")
			clientFlags.PrintDefaults()
		} else if *actionClient == "load" {
			if *interfacesClient == "" && *modeClient == "" {
				log.Print("Interfaces or mode flags cannot be empty")
				clientFlags.PrintDefaults()
			}
			err := clientApp.LoadXDP(*interfacesClient, *modeClient)
			if err != nil {
				log.Fatal(err)
			}
		}

	} else {
		log.Fatal(defMessage)
	}
}
