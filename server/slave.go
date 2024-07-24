package main

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/ahsifer/goxdp/helpers"
	"github.com/cilium/ebpf"
)

func unmarshalJSON(jsonData io.ReadCloser) (*MasterResponse, error) {
	var response MasterResponse
	err := json.NewDecoder(jsonData).Decode(&response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func createIPlistMap(permanentBlocked []string, cliBlocked []MasterCLIBlock) (map[BpfIpv4LpmKey]bool, map[BpfIpv4LpmKey]int) {
	ipMap := make(map[BpfIpv4LpmKey]bool)
	timeoutMap := make(map[BpfIpv4LpmKey]int)

	for _, cli := range cliBlocked {
		var key BpfIpv4LpmKey
		key.Prefixlen, key.Saddr, _ = helpers.PrepareXDPIP(cli.Src)
		ipMap[key] = true
		if cli.Timeout != 0 {
			timeoutMap[key] = cli.Timeout
		}
	}
	for _, ip := range permanentBlocked {
		var key BpfIpv4LpmKey
		key.Prefixlen, key.Saddr, _ = helpers.PrepareXDPIP(ip)
		ipMap[key] = true
	}

	return ipMap, timeoutMap
}

func updateBlockedIPs(currentBlockedIPs []internalIP, ipMap map[BpfIpv4LpmKey]bool) ([]BpfIpv4LpmKey, []BpfIpv4LpmKey) {
	toUnblock := []BpfIpv4LpmKey{}
	toBlock := []BpfIpv4LpmKey{}

	currentBlockedInIpMap := make(map[BpfIpv4LpmKey]bool)
	//check if the IP address from the current blocked IP addresses does not included in the list of the IP addresses that we want to block from the master (ipMap)
	for _, ip := range currentBlockedIPs {
		if !ipMap[ip.key] {
			if !ip.cliBlocked {
				toUnblock = append(toUnblock, ip.key)
			}
		} else {
			currentBlockedInIpMap[ip.key] = true
		}
	}
	//if the IP address exits on the ipMap but not from the current Blocked IP addresses (currentBlockedInIpMap) the we need to block them
	for ip := range ipMap {
		if !currentBlockedInIpMap[ip] {
			toBlock = append(toBlock, ip)
		}
	}
	return toBlock, toUnblock
}

func (app *Application) SlaveBlockedManager() error {
	app.InfoLog.Println("This the already blocked array before pulling --> ")
	for index1, value1 := range app.BlockedList {
		app.InfoLog.Println(index1, value1.key.Saddr, helpers.IntToIPv4(value1.key.Saddr))

	}
	app.InfoLog.Println("This the already blocked hash map before pulling--> ", app.BlockedListPointers)
	app.InfoLog.Println("This the already blocked timeout hash map before pulling--> ", app.TimeoutList)

	resp, err := app.SlaveClient.Get(app.MasterURL + "/status")
	if err != nil {
		return errors.New("Error in sending GET request to the master -> " + err.Error())
	}
	defer resp.Body.Close()
	marshaledData, err := unmarshalJSON(resp.Body)
	if err != nil {
		return errors.New("Error in parsing returned response from the master --> " + err.Error())
	}
	ipMap, timeoutMap := createIPlistMap(marshaledData.PermanentBlocked, marshaledData.CLIBlocked)
	toBlock, toUnblock := updateBlockedIPs(app.BlockedList, ipMap)
	app.InfoLog.Println("This the toBlock array --> ")
	for index1, value1 := range toBlock {
		app.InfoLog.Println(index1, value1.Saddr, helpers.IntToIPv4(value1.Saddr))

	}
	app.InfoLog.Println("This the toUnblock array --> ")
	for index1, value1 := range toUnblock {
		app.InfoLog.Println(index1, value1.Saddr, helpers.IntToIPv4(value1.Saddr))

	}
	//block the IP addresses from the master
	for _, value := range toBlock {
		//Block the IP address and update the MasterBlockedList slice
		err = app.BpfObjects.BlockedIpv4.Update(&value, uint8(1), ebpf.UpdateAny)
		if err != nil {
			app.ErrorLog.Println("Unable to insert into blocked_ipv4 LPM map --> " + err.Error())
		}
		tempInternalIP := internalIP{
			key:        value,
			cliBlocked: false,
		}
		app.BlockedList = append(app.BlockedList, tempInternalIP)
		app.BlockedListPointers[value] = len(app.BlockedList) - 1
		//check if the IP address has timeout value to block it with the timeout
		timeout, ok := timeoutMap[value]
		if ok {
			app.TimeoutList[value] = time.Now().Add(time.Duration(timeout) * time.Second)
		}
	}
	for _, value := range toUnblock {
		err = app.BpfObjects.BlockedIpv4.Delete(&value)
		if err != nil {
			app.ErrorLog.Println("Cannot unblock the IP address it might be already blocked -->" + err.Error())
		}
		//get element index in the BlockedList array from the BlockedListPointers
		//At this point we know that the IP address is already blocked. Therefore, no need to check if the IP address exists in the BlockedListPointers map
		lastElement := app.BlockedList[len(app.BlockedList)-1]
		index := app.BlockedListPointers[value]
		app.BlockedList = helpers.RemoveAndResliceArrayMap(app.BlockedList, index)
		app.BlockedListPointers[lastElement.key] = index
		delete(app.BlockedListPointers, value)
		delete(app.TimeoutList, value)
	}
	app.PullCounter = marshaledData.PullCounter
	app.InfoLog.Println("This the already blocked array after pulling --> ")
	for index1, value1 := range app.BlockedList {
		app.InfoLog.Println(index1, value1.key.Saddr, helpers.IntToIPv4(value1.key.Saddr))

	}
	app.InfoLog.Println("This the already blocked hash map after pulling--> ", app.BlockedListPointers)
	app.InfoLog.Println("This the already blocked timeout hash map after pulling--> ", app.TimeoutList)
	return nil
}
