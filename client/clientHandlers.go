package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
)

type ClientAPP struct {
	ServerIP   string
	ServerPort string
}

type ErrorStatusMessage struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func (app *ClientAPP) LoadXDP(interfaces string, mode string) (string, error) {
	//Encode the data
	postBody, err := json.Marshal(map[string]string{
		"interfaces": interfaces,
		"mode":       mode,
	})
	if err != nil {
		return "", errors.New("cannot marshal json data -> " + err.Error())
	}
	requestBody := bytes.NewBuffer(postBody)
	resp, err := http.Post("http://"+app.ServerIP+":"+app.ServerPort+"/load", "application/json", requestBody)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		return "XDP Program loaded successfully", nil
	} else {
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.NewDecoder(resp.Body).Decode(&errorMessage)
		if err != nil {
			return "", errors.New("Bad Json Returned from the server ->: %v" + err.Error())
		}
		return errorMessage.Message, nil
	}
}

func (app *ClientAPP) UnloadXDP(interfaces string) (string, error) {
	//Encode the data
	postBody, err := json.Marshal(map[string]string{
		"interfaces": interfaces,
	})
	if err != nil {
		return "", errors.New("cannot marshal json data -> " + err.Error())
	}
	requestBody := bytes.NewBuffer(postBody)
	resp, err := http.Post("http://"+app.ServerIP+":"+app.ServerPort+"/unload", "application/json", requestBody)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		return "XDP Program unloaded successfully to " + interfaces, nil
	} else {
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.NewDecoder(resp.Body).Decode(&errorMessage)
		if err != nil {

			return "", errors.New("Bad Json Returned from the server ->: %v" + err.Error())
		}
		return errorMessage.Message, nil
	}
}

func (app *ClientAPP) BlockXDP(action string, src string, timeout uint) (string, error) {
	//Encode the data
	postBody, err := json.Marshal(map[string]any{
		"action":  action,
		"src":     src,
		"timeout": timeout,
	})
	if err != nil {
		return "", errors.New("cannot marshal json data -> " + err.Error())
	}
	requestBody := bytes.NewBuffer(postBody)
	resp, err := http.Post("http://"+app.ServerIP+":"+app.ServerPort+"/block", "application/json", requestBody)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		if action == "allow" {
			return "src is allowed successfully", nil
		} else {
			return "src is blocked successfully", nil
		}
	} else {
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.NewDecoder(resp.Body).Decode(&errorMessage)
		if err != nil {

			return "", errors.New("Bad Json Returned from the server ->: %v" + err.Error())
		}
		return errorMessage.Message, nil
	}
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

func (app *ClientAPP) StatusXDP() (string, error) {

	resp, err := http.Get("http://" + app.ServerIP + ":" + app.ServerPort + "/status")
	if err != nil {
		return "", errors.New("Error in sending GET request -> " + err.Error())
	}
	defer resp.Body.Close()
	var message statusMapOutput
	//Parse json body
	err = json.NewDecoder(resp.Body).Decode(&message)
	if err != nil {

		return "", errors.New("Bad Json Returned from the server ->: %v" + err.Error())
	}
	// print the loaded network interfaces
	outMsg := "Loaded Interfaces are:\n"
	for index, value := range message.Interfaces {
		outMsg += fmt.Sprintf("\t%d- %s\n", index+1, value)
	}
	//Print blocked IP addresses
	outMsg += "\nBlocked IP address are:\n"
	for index, value := range message.Blocked {
		outMsg += fmt.Sprintf("\t%d- %s\n", index+1, value)
	}

	//Print Timeout table
	outMsg += "\nFiltered IP addresses' timeouts:\n"
	outMsg += "\tIP Address\t\t\tTimeout\t\t\tRemaining Time\n"

	for index, value := range message.Timeout {
		outMsg += fmt.Sprintf("\t%d- %s\t\t\t%s\t%ds\n", index+1, value.Src, value.Timeout, value.Remaining)
	}

	//Print stats table
	outMsg += "\nFiltered IP addresses' status:\n"
	outMsg += "\tIP Address\t\t\tRx_count\t\tBytes_dropped\n"
	for index, value := range message.Status {
		outMsg += fmt.Sprintf("\t%d- %s\t\t\t%d\t\t\t%d\n", index+1, value.Src, value.Rx_packets, value.Size_packets)
	}
	return outMsg, nil
}

func (app *ClientAPP) FlushStatusXDP() (string, error) {
	resp, err := http.Post("http://"+app.ServerIP+":"+app.ServerPort+"/flushstatus", "application/json", nil)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		return "Flushed successfully", nil
	} else {
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.NewDecoder(resp.Body).Decode(&errorMessage)
		if err != nil {

			return "", errors.New("Bad Json Returned from the server ->: %v" + err.Error())
		}
		return errorMessage.Message, nil
	}
}

func (app *ClientAPP) FlushBlockedXDP() (string, error) {
	resp, err := http.Post("http://"+app.ServerIP+":"+app.ServerPort+"/flushblocked", "application/json", nil)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		return "Flushed successfully", nil
	} else {
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.NewDecoder(resp.Body).Decode(&errorMessage)
		if err != nil {

			return "", errors.New("Bad Json Returned from the server ->: %v" + err.Error())
		}
		return errorMessage.Message, nil
	}
}
