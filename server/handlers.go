package main

import (
	"encoding/json"
	"fmt"
	"github.com/ahsifer/GoXDP/helpers"
	"github.com/dropbox/goebpf"
	"github.com/go-chi/chi/v5"
	"log"
	"net/http"
	"os/exec"
)

type DataLoad struct {
	// Action    *string `json:"action"`
	Interface *string `json:"interface"`
	Mode      *string `json:"mode"`
}

func xdpLoad(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	var body DataLoad
	//Parse json body
	err := json.NewDecoder(request.Body).Decode(&body)

	if err != nil {
		strRes := fmt.Sprintf("Unable to attach data to the interface Error: %s", err)
		log.Print(strRes)
		helpers.Error(response, strRes, http.StatusBadRequest)
		return
	}

	if *body.Mode == "" || *body.Interface == "" {
		strRes := fmt.Sprintf("Interface name and mode cannot be empty Error: %s", err)
		log.Print(strRes)
		helpers.Error(response, strRes, http.StatusBadRequest)
		return
	}

	//Create Modes Array
	modes := make(map[string]goebpf.XdpAttachMode)
	modes["hw"] = goebpf.XdpAttachModeHw
	modes["skb"] = goebpf.XdpAttachModeSkb
	modes["nv"] = goebpf.XdpAttachModeDrv

	finalMode, ok := modes[*body.Mode]
	if !ok {
		log.Printf("Error: bad Mode: %s", *body.Mode)
		helpers.Error(response, "Bad Mode", http.StatusBadRequest)
		return
	}
	interfaceParam := goebpf.XdpAttachParams{
		Interface: *body.Interface,
		Mode:      finalMode,
	}

	err = AppInstance.MainProgram.Attach(&interfaceParam)
	if err != nil {
		strRes := fmt.Sprintf("Unable to attach data to the interface Error: %s", err)
		log.Print(strRes)
		helpers.Error(response, strRes, http.StatusBadRequest)
		return
	}
	response.WriteHeader(200)
	return

}

func xdpUnload(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")

	interfaceName := chi.URLParam(request, "interface")
	if interfaceName == "" {
		strRes := fmt.Sprintf("Please provide interface name")
		log.Print(strRes)
		helpers.Error(response, strRes, http.StatusBadRequest)
		return
	}
	_, err := exec.Command("ip", "link", "set", "dev", interfaceName, "xdp", "off").Output()

	if err != nil {
		strRes := fmt.Sprintf("Unable to unload the XDP programme from the given interface")
		log.Print(strRes)
		helpers.Error(response, strRes, http.StatusBadRequest)
		return
	}
	response.WriteHeader(200)
	return

}
