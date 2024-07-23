package master

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/ahsifer/goxdp/helpers"
)

func (mApp *MasterAPP) xdpBlockAllow(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	//Request body parsing
	var body BlockedCliIP
	err := json.NewDecoder(request.Body).Decode(&body)
	if err != nil {
		mApp.ErrorLog.Printf("Cannot parse json request -> %v\n", err)
		helpers.Error(response, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	// check for empty inputs
	if body.Src == nil || body.Action == nil || body.Timeout == nil {
		mApp.ErrorLog.Printf("Request body does not include src, action, or timeout")
		helpers.Error(response, "Request body does not include src, action, or timeout", http.StatusBadRequest)
		return
	}

	//Check if input IP is valid
	validIP, err := helpers.IpChecker(*body.Src)
	if err != nil {
		mApp.ErrorLog.Printf("Invalid IP address or subnet -> %s", err)
		helpers.Error(response, "Invalid Request Body", http.StatusBadRequest)
	}
	stringSlice := strings.Split(*validIP, "/")
	_, err = strconv.ParseUint(stringSlice[1], 10, 32)
	if err != nil {
		errMsg := "Input prefix cannot be parsed to unit32 (Might be bad input prefix) -> " + err.Error()
		mApp.ErrorLog.Print(errMsg)
		helpers.Error(response, errMsg, http.StatusBadRequest)
		return
	}

	mApp.InfoLog.Println("Received Request from " + request.Header.Get("username") + " to " + *body.Action + " The following " + *body.Src)
	if *body.Action == "block" {
		err = mApp.CliAddBlockedIP(*body.Src, *body.Timeout)
		if err != nil {
			mApp.ErrorLog.Println(err)
			helpers.Error(response, err.Error(), http.StatusBadRequest)
			return
		}
	} else if *body.Action == "allow" {
		err = mApp.RemoveBlockedIP(*body.Src, true)
		if err != nil {
			mApp.ErrorLog.Println(err)
			helpers.Error(response, err.Error(), http.StatusBadRequest)

			return
		}
	} else {
		helpers.Error(response, "Bad input action", http.StatusBadRequest)
	}
	response.WriteHeader(200)
	// return
}

func (mApp *MasterAPP) xdpStatus(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	var output InternalConfigJson

	//prepare our output
	output.PullCounter = mApp.PullCounter
	output.PermBlockedIPsArray = mApp.PermBlockedIPsArray
	output.CliBlockedIPsArray = mApp.CliBlockedIPsArray

	finalResponse, err := json.Marshal(output)
	if err != nil {
		mApp.ErrorLog.Println("xdpStatus: Unable to parse json data", err)
		helpers.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	response.Write(finalResponse)
}

func (mApp *MasterAPP) xdpBlockedFlush(response http.ResponseWriter, request *http.Request) {
	mApp.InfoLog.Println("Received request to flush all the blocked IP addresses from " + request.Header.Get("username"))
	//Empty all the CLI array and the hash map
	mApp.CliBlockedIPsArray = []BlockedCliIP{}
	mApp.CliBlockedIPsHashMap = map[string]int{}
	mApp.PullCounter++
	mApp.WriteInternalConf()
	response.WriteHeader(200)
}

func (mApp *MasterAPP) xdpGetPullCounter(response http.ResponseWriter, request *http.Request) {
	output := PullCounterRes{
		PullCounter: mApp.PullCounter,
	}
	finalResponse, err := json.Marshal(output)
	if err != nil {
		mApp.ErrorLog.Println("xdpPullCounter: Unable to parse json data", err)
		helpers.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	response.Write(finalResponse)
}

func (mApp *MasterAPP) xdpIncrementPullCounter(response http.ResponseWriter, request *http.Request) {
	mApp.InfoLog.Println("Received request to increment the pull counter from " + request.Header.Get("username"))
	mApp.PullCounter++
	mApp.WriteInternalConf()
	response.WriteHeader(200)
}

func (mApp *MasterAPP) xdpReloadConf(response http.ResponseWriter, request *http.Request) {
	err := mApp.LoadBlockedConf()
	if err != nil {
		mApp.ErrorLog.Fatal(err)
		helpers.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

	}

	//load the authentication file from auth.json
	err = mApp.LoadAuthConfig()
	if err != nil {
		mApp.ErrorLog.Fatal(err)
		helpers.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

	}

	//load the slaves configuration file from slaves.json
	err = mApp.LoadSlavesConfig()
	if err != nil {
		mApp.ErrorLog.Fatal(err)
		helpers.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

	}

	//load the Internal configuration file contents into the memory
	err = mApp.LoadInternalConf()

	if err != nil {
		mApp.ErrorLog.Fatal(err)
		helpers.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

	}
	mApp.PullCounter++
	response.WriteHeader(200)

}
