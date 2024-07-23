package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"time"

	"github.com/ahsifer/goxdp/client"
	"github.com/ahsifer/goxdp/helpers"
	"github.com/ahsifer/goxdp/master"
	"github.com/cilium/ebpf/link"

	"log"
	"net/http"
	"os"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ../source/xdp.c -- -I../headers

func main() {
	defMessage := "Error: Bad input parameters:> \nUsage:\n \tgoxdp <command> <options> \navailable commands are:\n\tserver \tstart XDP HTTP server for handling users requests\n\tclient\tinteract with the XDP server\n \tmaster\tstart the master service\nFlags:\n\t-h,--h\tfor help"
	if len(os.Args) <= 1 {
		log.Fatal(defMessage)
	}

	//Handling server flags
	serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
	privateIP := serverFlags.String("privateIP", "127.0.0.1", "The private IP address the service will listen to, that will be used to respond to load,unload,block,allow, and status requests")
	privatePort := serverFlags.String("privatePort", "8090", "The private Port number the service will listen to")
	publicIP := serverFlags.String("publicIP", *privateIP, "The public IP address the service will listen to that will be used to respond to metrics and status requests")
	publicPort := serverFlags.String("publicPort", "8091", "The public Port number the service will listen to")
	timeoutWorkerInterval := serverFlags.Int("timeoutInterval", 30, "The timeout interval of the worker thread to check if subnet or IP address timeout is finished")
	enMaster := serverFlags.Bool("master", false, "Enable master slave communication")
	validMasterSSL := serverFlags.Bool("validSSL", false, "Enable when the master uses valid SSL certificate (useful when the chosen protocol is https)")
	slaveMasterIP := serverFlags.String("masterIP", "127.0.0.1", "The IP address of the master service")
	slaveMasterPort := serverFlags.String("masterPort", "127.0.0.1", "The port number that the master service is listening to")
	slaveMasterProtocol := serverFlags.String("protocol", "http", "use http or https to communicate with the master")
	slavePullInterval := serverFlags.Int("masterPullInterval", 5, "The timeout interval between checking for updates from the master")

	// Handling Client Flags
	clientFlags := flag.NewFlagSet("client", flag.ExitOnError)
	actionClient := clientFlags.String("action", "", "Available values are load,unload,block, allow, status (Also incremental and reload can be used with the master service)")
	interfacesClient := clientFlags.String("interfaces", "", "Interfaces names that the XDP programme will be loaded to (Example 'eth0,eth1')")
	modeClient := clientFlags.String("mode", "", "The mode that XDP programme will be loaded (available modes are nv,skb, and hw)")
	srcClient := clientFlags.String("src", "", "src IP address or subnet that will be blocked or allowed")
	timeoutClient := clientFlags.Uint("timeout", 0, "How long the IP address or the subnet will be blocked in seconds")
	serverIPClient := clientFlags.String("dstIP", "127.0.0.1", "The IP address that the goxdp service is listening to")
	serverPortClient := clientFlags.String("dstPort", "8090", "The Port that the goxdp service is listening to")
	flush := clientFlags.Bool("flush", false, "Passed alongside with the actions status,block,allow to flush the status or blocked IP addresses or subnets tables")
	clientProtocol := clientFlags.String("protocol", "http", "use http or https (Useful when the master service using HTTPS)")
	validSSL := clientFlags.Bool("validSSL", false, "Validate destination certificate when protocol parameter is true (Useful when the master service is using valid certificate)")
	targetMaster := clientFlags.Bool("master", false, "Destination hosts is master or not")
	username := clientFlags.String("username", "", "Useful when contacting the master service")
	token := clientFlags.String("token", "", "Useful when contacting the master service")

	//Handling Master Flags
	masterFlags := flag.NewFlagSet("master", flag.ExitOnError)
	masterSrvIP := masterFlags.String("IP", "127.0.0.1", "The IP address the master service will listen to")
	masterSrvPort := masterFlags.String("Port", "8090", "The Port number the master service will listen to")
	authConfigFile := masterFlags.String("authConfPath", "/etc/goxdp/auth.json", "Path to the authentication config file")
	slavesConfigFile := masterFlags.String("slavesConfPath", "/etc/goxdp/slaves.json", "Path to the slave nodes config file)")
	certFilePath := masterFlags.String("certFilePath", "/etc/goxdp/cert.pem", "Path to certificate file")
	keyFilePath := masterFlags.String("keyFilePath", "/etc/goxdp/key.pem", "Path to key file")
	masterSslEn := masterFlags.Bool("enableSSl", true, "Enable SSL on Master communication")
	permBlockedConfigFile := masterFlags.String("blockedFilePath", "/etc/goxdp/blocked.list", "Path to the file that include the initial IP addresses and subnets that needs to be blocked in all the slaves once the master service starts")
	internalConfPath := masterFlags.String("internalConfPath", "/etc/goxdp/internal.json", "Path to the auto generated file that used to store the information about all the blocked IP addresses and subnets that have been added using CLI or restful API to keep them permanent after restarts")
	masterTimeoutCheckerInterval := masterFlags.Int("timeoutCheckerInterval", 5, "The timeout interval in seconds that the master service will check if the timeout of blocked IP address or subnet is finished")
	autoPropagate := masterFlags.Bool("autoPropagate", false, "Retransmit the blocked IP addresses ot all the slaves when master starts or restart")

	//defining logging constants
	var globalInfoLog *log.Logger = log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	var globalErrorLog *log.Logger = log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)
	if os.Args[1] == "server" {
		serverFlags.Parse(os.Args[2:])
		//Instance of the application struct
		app := Application{
			InfoLog:             globalInfoLog,
			ErrorLog:            globalErrorLog,
			LoadedInterfaces:    map[string]link.Link{},
			TimeoutList:         map[BpfIpv4LpmKey]time.Time{},
			BlockedList:         []internalIP{},
			BlockedListPointers: map[BpfIpv4LpmKey]int{},
			PullCounter:         0,
			MasterURL:           *slaveMasterProtocol + "://" + *slaveMasterIP + ":" + *slaveMasterPort,
			MasterSSL:           *validMasterSSL,
			SlaveClient:         &http.Client{},
		}
		//check if user entered correct timeout interval for the timeout worker
		if *timeoutWorkerInterval < 5 {
			app.ErrorLog.Fatal("TimeoutWorkerInterval should 5 or greater")
		}
		//start timeout worker
		go app.timeoutWorker(*timeoutWorkerInterval)
		//start slave worker
		if !*validMasterSSL {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			app.SlaveClient = &http.Client{Transport: tr}
		}
		//Handling username and token for authentication purposes
		// if *username!="" && *token!=""{
		// 	app.SlaveClient.Transport=&http.
		// }

		if *enMaster {
			go app.slavePuller(*slavePullInterval)
		}
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
			Handler:  app.serverPublicRouter(),
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
			ErrorLog: globalErrorLog,
			Handler:  app.serverPrivateRouter(),
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

		//disable https certificate verification
		if *clientProtocol == "https" && !*validSSL {
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}

		//Create new clientApp struct
		clientApp := client.ClientAPP{
			ServerURL:    *clientProtocol + "://" + *serverIPClient + ":" + *serverPortClient,
			TargetMaster: *targetMaster,
			HttpClient:   &http.Client{},
		}
		//setup authentication if found
		if *username != "" && *token != "" {
			clientApp.HttpClient.Transport = &client.AuthRoundTripper{
				DefaultRoundTripper: http.DefaultTransport,
				Username:            *username,
				Token:               *token,
			}

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
			if *flush {
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
			msg, err := clientApp.BlockXDP(*actionClient, *srcClient, *timeoutClient)
			if err != nil {
				log.Fatal(err)
			}
			log.Print(msg)
		} else if *actionClient == "status" {
			if !*flush {
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

		} else if *actionClient == "increment" {
			msg, err := clientApp.IncPullCounter()
			if err != nil {
				log.Fatal(err)
			}
			log.Print(msg)
		} else if *actionClient == "reload" {
			msg, err := clientApp.ReloadMasterConf()
			if err != nil {
				log.Fatal(err)
			}
			log.Print(msg)
		}

	} else if os.Args[1] == "master" {
		//Parse the input arguments
		masterFlags.Parse(os.Args[2:])

		//create instance of the MasterAPP struct
		masterApp := master.MasterAPP{
			InfoLog:               globalInfoLog,
			ErrorLog:              globalErrorLog,
			SlavesConfigFile:      *slavesConfigFile,
			AuthConfigFile:        *authConfigFile,
			AuthUsers:             map[string]string{},
			PermBlockedConfigFile: *permBlockedConfigFile,
			InternalConfPath:      *internalConfPath,
			AutoPropagate:         *autoPropagate,
			PullCounter:           1, //on start the value of the pull counter
			PermBlockedIPsArray:   []string{},
			PermBlockedIPsHashMap: map[string]int{},
			CliBlockedIPsArray:    []master.BlockedCliIP{},
			CliBlockedIPsHashMap:  map[string]int{},
		}

		//load the blocked IP addresses from blocked.list
		err := masterApp.LoadBlockedConf()
		if err != nil {
			globalErrorLog.Fatal(err)
		}
		//load the authentication file from auth.json
		err = masterApp.LoadAuthConfig()
		if err != nil {
			globalErrorLog.Fatal(err)
		}

		//load the slaves configuration file from slaves.json
		err = masterApp.LoadSlavesConfig()
		if err != nil {
			globalErrorLog.Fatal(err)
		}

		//load the Internal configuration file contents into the memory
		err = masterApp.LoadInternalConf()
		if err != nil {
			globalErrorLog.Fatal(err)
		}

		// globalInfoLog.Println("Test2")
		// masterApp.RemoveBlockedIP("2.3.45.6")
		// globalInfoLog.Println(masterApp.PermBlockedIPsArray)
		// globalInfoLog.Println(masterApp.PermBlockedIPsHashMap)
		// globalInfoLog.Println(masterApp.CliBlockedIPsArray)
		// globalInfoLog.Println(masterApp.CliBlockedIPsHashMap)
		// globalInfoLog.Println("\n\n\n")

		// globalInfoLog.Println("Test3")
		// masterApp.RemoveBlockedIP("123.159.0.0/16")
		// globalInfoLog.Println(masterApp.PermBlockedIPsArray)
		// globalInfoLog.Println(masterApp.PermBlockedIPsHashMap)
		// globalInfoLog.Println(masterApp.CliBlockedIPsArray)
		// globalInfoLog.Println(masterApp.CliBlockedIPsHashMap)

		//start the timeout checker service
		go masterApp.TimeoutChecker(*masterTimeoutCheckerInterval)
		//begin web server configuration
		masterSrv := &http.Server{
			Addr:     fmt.Sprintf("%s:%s", *masterSrvIP, *masterSrvPort),
			ErrorLog: globalErrorLog,
			Handler:  masterApp.MasterAllRoutes(),
		}
		masterApp.InfoLog.Printf("Starting the master server on IP: %s, Port: %s ....", *masterSrvIP, *masterSrvPort)
		masterApp.InfoLog.Printf("Started successfully on IP: %s, Port: %s waiting for block,allow,flush and status requests", *privateIP, *privatePort)
		//setup SSL certificate
		if *masterSslEn {
			globalInfoLog.Println("starting ssl configuration")
			serverTLSCert, err := tls.LoadX509KeyPair(*certFilePath, *keyFilePath)
			if err != nil {
				log.Fatalf("Error loading certificate and key file Err: %v", err)
			}
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{serverTLSCert},
			}
			masterSrv.TLSConfig = tlsConfig

			err = masterSrv.ListenAndServeTLS(*certFilePath, *keyFilePath)
			if err != nil {
				masterApp.ErrorLog.Fatal(err)
			}
		} else {
			err = masterSrv.ListenAndServe()
			if err != nil {
				masterApp.ErrorLog.Fatal(err)
			}
		}

	} else {
		log.Fatal(defMessage)
	}
}
