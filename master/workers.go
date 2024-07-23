package master

import (
	"time"
)

// remove blocked IP addresses with finished timeout from CliBlockedIPsArray
func (mApp *MasterAPP) TimeoutChecker(interval int) {
	mApp.InfoLog.Printf("Starting timeout checker worker with interval of %d", interval)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	for range ticker.C {
		tempArrayAllow := []string{}
		for index, val := range mApp.CliBlockedIPsArray {
			//Timeout with nil value means block forever
			if val.Timeout == nil {
				continue
			}
			//Remove entries with timeout of value 0
			if *(val.Timeout) <= 0 {
				tempArrayAllow = append(tempArrayAllow, *(val.Src))
			}

			//reduce the timeout interval of elements with timeouts
			*(mApp.CliBlockedIPsArray[index].Timeout) -= interval

		}
		// This cannot be added in the above for loop because the RemoveBlockedIP will resize the array size and this will lead to wrong index value and then panic
		//Unblock all the IP addresses
		for _, val := range tempArrayAllow {
			mApp.RemoveBlockedIP(val, false)
		}
		//Write the internal config without incrementing the Pull counter, it is not required because all the slaves will unblock when timeout is finished
		mApp.WriteInternalConf()
	}
}
