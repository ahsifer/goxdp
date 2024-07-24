package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

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
	resp, err := app.HttpClient.Post(app.ServerURL+"/load", "application/json", requestBody)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		return "XDP Program loaded successfully", nil
	} else {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", errors.New("error reading response body -> " + err.Error())
		}
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.Unmarshal(bodyBytes, &errorMessage)
		if err != nil {
			return "", errors.New(string(bodyBytes))
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
	resp, err := app.HttpClient.Post(app.ServerURL+"/unload", "application/json", requestBody)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		return "XDP Program unloaded successfully to " + interfaces, nil
	} else {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", errors.New("error reading response body -> " + err.Error())
		}
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.Unmarshal(bodyBytes, &errorMessage)
		if err != nil {
			return "", errors.New(string(bodyBytes))
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
	resp, err := app.HttpClient.Post(app.ServerURL+"/block", "application/json", requestBody)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()
	//read response data
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("error reading response body -> " + err.Error())
	}

	if resp.Status == "200 OK" {
		if action == "allow" {
			return "src is allowed successfully", nil
		} else {
			return "src is blocked successfully", nil
		}
	} else {
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.Unmarshal(bodyBytes, &errorMessage)
		if err != nil {
			return "", errors.New(string(bodyBytes))
		}
		return errorMessage.Message, nil
	}
}

func (app *ClientAPP) StatusXDP() (string, error) {

	resp, err := app.HttpClient.Get(app.ServerURL + "/status")
	if err != nil {
		return "", errors.New("Error in sending GET request -> " + err.Error())
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("error reading response body -> " + err.Error())
	}

	if !app.TargetMaster {
		var message statusMapOutput
		//Parse json body

		err = json.Unmarshal(bodyBytes, &message)
		if err != nil {
			return "", errors.New(string(bodyBytes))
		}
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
			outMsg += fmt.Sprintf("\t%d- %s\t\t%s\t%ds\n", index+1, value.Src, value.Timeout, value.Remaining)
		}

		//Print stats table
		outMsg += "\nFiltered IP addresses' status:\n"
		outMsg += "\tIP Address\t\t\tRx_count\t\tBytes_dropped\n"
		for index, value := range message.Status {
			outMsg += fmt.Sprintf("\t%d- %s\t\t\t%d\t\t\t%d\n", index+1, value.Src, value.Rx_packets, value.Size_packets)
		}
		return outMsg, nil
	} else {
		//Handle master status response
		var message MasterStatus
		//Parse json body
		err = json.Unmarshal(bodyBytes, &message)
		if err != nil {
			return "", errors.New(string(bodyBytes))
		}
		indentedJson, err := json.MarshalIndent(message, "", "	")
		if err != nil {
			return "", errors.New("Cannot indents the returned json from the server ->: %v" + err.Error())
		}

		return string(indentedJson), nil
	}

}

func (app *ClientAPP) FlushStatusXDP() (string, error) {
	resp, err := app.HttpClient.Post(app.ServerURL+"/flushstatus", "application/json", nil)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		return "Flushed successfully", nil
	} else {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", errors.New("error reading response body -> " + err.Error())
		}
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.Unmarshal(bodyBytes, &errorMessage)
		if err != nil {
			return "", errors.New(string(bodyBytes))
		}
		return errorMessage.Message, nil
	}
}

func (app *ClientAPP) FlushBlockedXDP() (string, error) {
	resp, err := app.HttpClient.Post(app.ServerURL+"/flushblocked", "application/json", nil)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		return "Flushed successfully", nil
	} else {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", errors.New("error reading response body -> " + err.Error())
		}
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.Unmarshal(bodyBytes, &errorMessage)
		if err != nil {
			return "", errors.New(string(bodyBytes))
		}
		return errorMessage.Message, nil
	}
}

func (app *ClientAPP) IncPullCounter() (string, error) {
	resp, err := app.HttpClient.Post(app.ServerURL+"/increment", "application/json", nil)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		return "Pull counter incremented successfully", nil
	} else {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", errors.New("error reading response body -> " + err.Error())
		}
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.Unmarshal(bodyBytes, &errorMessage)
		if err != nil {
			return "", errors.New(string(bodyBytes))
		}
		return errorMessage.Message, nil
	}
}

func (app *ClientAPP) ReloadMasterConf() (string, error) {
	resp, err := app.HttpClient.Post(app.ServerURL+"/reload", "application/json", nil)
	if err != nil {
		return "", errors.New("Error in sending POST request -> " + err.Error())
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		return "Reloaded successfully", nil
	} else {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", errors.New("error reading response body -> " + err.Error())
		}
		var errorMessage ErrorStatusMessage
		//Parse json body
		err = json.Unmarshal(bodyBytes, &errorMessage)
		if err != nil {
			return "", errors.New(string(bodyBytes))
		}
		return errorMessage.Message, nil
	}
}
