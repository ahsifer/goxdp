package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/ahsifer/goxdp/client"
	"github.com/ahsifer/goxdp/helpers"
	"github.com/cilium/ebpf/link"

	"log"
	"net/http"
	"os"
	// "strings"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ../source/xdp.c -- -I../headers

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
	timeoutClient := clientFlags.Uint("timeout", 0, "How long the IP address or the subnet will be blocked in seconds")
	serverIPClient := clientFlags.String("ip", "127.0.0.1", "How long the IP address or the subnet will be blocked in seconds")
	serverPortClient := clientFlags.String("port", "8090", "How long the IP address or the subnet will be blocked in seconds")

	if os.Args[1] == "server" {
		serverFlags.Parse(os.Args[2:])
		//Instance of the application struct
		app := Application{
			InfoLog:          log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime),
			ErrorLog:         log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile),
			LoadedInterfaces: map[string]link.Link{},
			TimeoutList:      map[BpfIpv4LpmKey]time.Time{},
			// Is_loaded:        false,
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
		//remove timestamps from the returned logs
		// newLogger := log.New(os.Stdout, "INFO\t",)
		log.SetFlags(0)
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
			msg, err := clientApp.LoadXDP(*interfacesClient, *modeClient)
			if err != nil {
				log.Fatal(err)
			}
			log.Print(msg)
		} else if *actionClient == "unload" {
			if *interfacesClient == "" && *modeClient == "" {
				log.Print("Interfaces names cannot be empty")
				clientFlags.PrintDefaults()
			}
			msg, err := clientApp.UnloadXDP(*interfacesClient)
			if err != nil {
				log.Fatal(err)
			}
			log.Print(msg)
		} else if *actionClient == "allow" || *actionClient == "block" {
			//check if IP address or subnet is valid
			if _, err := helpers.IpChecker(*srcClient); err != nil {
				log.Fatal(err)
			}
			if *timeoutClient < 0 {
				log.Fatal("timeout cannot be less than zero")
			}
			msg, err := clientApp.BlockXDP(*actionClient, *srcClient, *timeoutClient)
			if err != nil {
				log.Fatal(err)
			}
			log.Print(msg)
		} else if *actionClient == "status" {
			msg, err := clientApp.StatusXDP()
			if err != nil {
				log.Fatal(err)
			}
			log.Print(msg)
		}

	} else {
		log.Fatal(defMessage)
	}
}
