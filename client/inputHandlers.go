package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
)

type ClientAPP struct {
	ServerIP   string
	ServerPort string
}

func (app *ClientAPP) LoadXDP(interfaces string, mode string) error {
	//Encode the data
	postBody, err := json.Marshal(map[string]string{
		"interfaces": interfaces,
		"mode":       mode,
	})
	if err != nil {
		return errors.New(fmt.Sprintf("cannot marshal json data -> %s", err))
	}
	requestBody := bytes.NewBuffer(postBody)
	resp, err := http.Post("http://"+app.ServerIP+":"+app.ServerPort+"/load", "application/json", requestBody)
	if err != nil {
		return errors.New(fmt.Sprintf("Error in sending POST request -> %s", err))
	}
	defer resp.Body.Close()

	if resp.Status == "200 OK" {
		log.Print("XDP Programme loaded successfully")
	} else {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("unable to read response body -> %s", err)
		}
		log.Fatal(string(body))
	}

	return nil
}
