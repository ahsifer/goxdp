package main

import (
	"github.com/ahsifer/goxdp/helpers"
	"time"
)

func (app *Application) timeoutWorker(interval int) {
	app.InfoLog.Printf("Starting timeout checker worker with interval of %d", interval)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	for range ticker.C {
		currentTime := time.Now()
		for key, value := range app.TimeoutList {
			if currentTime.After(value) {
				err := app.BpfObjects.BlockedIpv4.Delete(&key)
				if err != nil {
					app.InfoLog.Print("TimeoutWorker error cannot delete the key ", key, " from the blockedIPv4 map -> ", err)
				}
				//remove the IP address from the blockedList of IP addresses and from the TimeoutList
				//1- get last element form the array to replace it with the element we want to delete
				lastElement := app.BlockedList[len(app.BlockedList)-1]
				index := app.BlockedListPointers[key]
				app.BlockedList = helpers.RemoveAndResliceArrayMap(app.BlockedList, index)
				app.BlockedListPointers[lastElement.key] = index
				delete(app.BlockedListPointers, key)
				delete(app.TimeoutList, key)
			}
		}

	}

}
func (app *Application) slavePuller(interval int) {
	app.InfoLog.Printf("Starting slave worker with interval of %d", interval)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)

	for range ticker.C {
		// get Pull counter value from the master
		resp, err := app.SlaveClient.Get(app.MasterURL + "/pullcounter")
		if err != nil {
			app.ErrorLog.Println("Error in sending GET request -> " + err.Error())
			continue
		}
		if resp.StatusCode != 200 {
			app.ErrorLog.Println("Bad response status code from the master")
			continue
		}
		marshaledData, err := unmarshalJSON(resp.Body)
		if err != nil {
			app.ErrorLog.Println("Error in parsing returned response from the master --> " + err.Error())
		}
		//check unmatched Pull counter values to pull data from the master
		if app.PullCounter != marshaledData.PullCounter {
			app.InfoLog.Println("Syncing with the master")
			err = app.SlaveBlockedManager()
			if err != nil {
				app.ErrorLog.Println(err.Error())
				continue
			}
			//update the pull counter
			app.PullCounter = marshaledData.PullCounter
			app.InfoLog.Println("Syncing with the master done successfully")

		}
		resp.Body.Close()

	}
}
