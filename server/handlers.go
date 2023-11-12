package main

import (
	"encoding/json"
	"fmt"
	"github.com/ahsifer/GoXDP/helpers"
	"github.com/dropbox/goebpf"
	"log"
	"net/http"
)

type DataLoad struct {
	Action    *string `json:"action"`
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
	if *body.Action == "load" {
		if *body.Mode != "" && *body.Interface != "" {
			//Create Modes Array
			modes := make(map[string]goebpf.XdpAttachMode)
			modes["hw"] = goebpf.XdpAttachModeHw
			modes["skb"] = goebpf.XdpAttachModeSkb
			modes["nv"] = goebpf.XdpAttachModeDrv
			finalMode, ok := modes[*body.Mode]
			if !ok {
				log.Printf("User Entered bad Mode: %s", *body.Mode)
				helpers.Error(response, "Bad Mode", http.StatusBadRequest)
				return
			}
			interfaceParam := goebpf.XdpAttachParams{
				Interface: *body.Interface,
				Mode:      finalMode,
			}

			err = AppInstance.Program.Attach(&interfaceParam)
			if err != nil {
				strRes := fmt.Sprintf("Unable to attach data to the interface Error: %s", err)
				log.Print(strRes)
				helpers.Error(response, strRes, http.StatusBadRequest)
				return
			}
			return
		} else {
			strRes := fmt.Sprintf("Interface name and mode cannot be empty Error: %s", err)
			log.Print(strRes)
			helpers.Error(response, strRes, http.StatusBadRequest)
			return
		}
	}

}
