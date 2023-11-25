package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
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
