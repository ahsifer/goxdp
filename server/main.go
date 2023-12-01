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
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ../source/xdp.c -- -I../headers

func main() {
	defMessage := "Error: Bad input parameters:> \nUsage:\n \tgoxdp <command> <options> \navailable commands are:\n\tserver \tstart XDP HTTP server for handling users requests\n\tclient\tinteract with the XDP server\nFlags:\n\t-h,--h\tfor help"
	if len(os.Args) <= 1 {
		log.Fatal(defMessage)
	}

	//Handling server flags
	serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
	privateIP := serverFlags.String("privateIP", "127.0.0.1", "The private IP address the service will listen to that will be used to respond to load,unload,block,allow, and status requests")
	privatePort := serverFlags.String("privatePort", "8090", "The private Port number the service will listen to")
	publicIP := serverFlags.String("publicIP", *privateIP, "The public IP address the service will listen to that will be used to respond to metrics and status requests")
	publicPort := serverFlags.String("publicPort", "8091", "The public Port number the service will listen to")
	timeoutWorkerInterval := serverFlags.Int("timeoutinterval", 30, "The timeout of the worker thread to check if subnet or IP address timeout is finished")
	// Handling Client Flags
	clientFlags := flag.NewFlagSet("client", flag.ExitOnError)
	actionClient := clientFlags.String("action", "", "Available values are load,unload,block, allow, status")
	interfacesClient := clientFlags.String("interfaces", "", "Interfaces names that the XDP programme will be loaded to (Example 'eth0,eth1')")
	modeClient := clientFlags.String("mode", "", "The mode that XDP programme will be loaded (available values are nv,skb, and hw)")
	srcClient := clientFlags.String("src", "", "src IP address or subnet that will be blocked or allowed")
	timeoutClient := clientFlags.Uint("timeout", 0, "How long the IP address or the subnet will be blocked in seconds")
	serverIPClient := clientFlags.String("dstIP", "127.0.0.1", "The IP address that the goxdp service is listening to")
	serverPortClient := clientFlags.String("dstPort", "8090", "The Port that the goxdp service is listening to")
	flush := clientFlags.Bool("flush", false, "Passed alongside with the actions status,block,allow to flush the status or blocked IP addresses or subnets tables")

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

		//Start public routes
		pubsrv := &http.Server{
			Addr:     fmt.Sprintf("%s:%s", *publicIP, *publicPort),
			ErrorLog: app.ErrorLog,
			Handler:  app.publicRouter(),
		}
		app.InfoLog.Printf("Starting public routes worker service on IP: %s, Port: %s ....", *publicIP, *publicPort)
		go func() {
			err := pubsrv.ListenAndServe()
			if err != nil {
				app.ErrorLog.Fatal(err)
			}
		}()
		app.InfoLog.Printf("Public routes worker service started successfully on IP: %s, Port: %s waiting for metrics and status requests", *publicIP, *publicPort)

		//Start private routes
		prvsrv := &http.Server{
			Addr:     fmt.Sprintf("%s:%s", *privateIP, *privatePort),
			ErrorLog: app.ErrorLog,
			Handler:  app.privateRouter(),
		}
		app.InfoLog.Printf("Starting server on IP: %s, Port: %s ....", *privateIP, *privatePort)
		app.InfoLog.Printf("Started successfully on IP: %s, Port: %s waiting for load,unload,block,allow, and status requests", *privateIP, *privatePort)
		err := prvsrv.ListenAndServe()
		if err != nil {
			app.ErrorLog.Fatal(err)
		}

	} else if os.Args[1] == "client" {
		//remove timestamps from the returned logs
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
			if *interfacesClient == "" || *modeClient == "" {
				log.Print("Interfaces or mode flags cannot be empty")
				clientFlags.PrintDefaults()
			}
			msg, err := clientApp.LoadXDP(*interfacesClient, *modeClient)
			if err != nil {
				log.Fatal(err)
			}
			log.Print(msg)
		} else if *actionClient == "unload" {
			if *interfacesClient == "" {
				log.Print("Interfaces names cannot be empty")
				clientFlags.PrintDefaults()
			}
			msg, err := clientApp.UnloadXDP(*interfacesClient)
			if err != nil {
				log.Fatal(err)
			}
			log.Print(msg)
		} else if *actionClient == "allow" || *actionClient == "block" {
			if *flush == true {
				msg, err := clientApp.FlushBlockedXDP()
				if err != nil {
					log.Fatal(err)
				}
				log.Print(msg)
				return
			}
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
			if *flush == false {
				msg, err := clientApp.StatusXDP()
				if err != nil {
					log.Fatal(err)
				}
				log.Print(msg)
			} else {
				//Handle if flush status is true
				msg, err := clientApp.FlushStatusXDP()
				if err != nil {
					log.Fatal(err)
				}
				log.Print(msg)
			}

		}

	} else {
		log.Fatal(defMessage)
	}
}
