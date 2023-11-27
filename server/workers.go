package main

import (
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
				delete(app.TimeoutList, key)
			}
		}

	}

}
