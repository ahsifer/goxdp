package master

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"

	// "time"

	"github.com/ahsifer/goxdp/helpers"
)

//setup internal blocked IP addresses and subnets in file

func (mApp *MasterAPP) LoadAuthConfig() error {
	var users AuthUsers
	configFile, err := os.Open(mApp.AuthConfigFile)
	if err != nil {
		return errors.New("Could not read authorized users JSON configuration file " + mApp.AuthConfigFile + " --> " + err.Error())
	}
	//check error on defer log the error
	defer func() {
		err := configFile.Close()
		if err != nil {
			mApp.InfoLog.Println(err)
		}
	}()
	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&users)
	if err != nil {
		return errors.New("Error parsing users JSON file " + mApp.AuthConfigFile + " --> " + err.Error())
	}
	tempUsersMap := map[string]string{}
	for _, user := range users {
		tempUsersMap[user.Name] = user.Token
	}
	mApp.AuthUsers = tempUsersMap
	mApp.InfoLog.Println("Finished reading " + mApp.AuthConfigFile + " file successfully")

	return nil
}

// load slave nodes configuration file
func (mApp *MasterAPP) LoadSlavesConfig() error {
	var slaves SlaveNodes
	configFile, err := os.Open(mApp.SlavesConfigFile)
	if err != nil {
		return errors.New("Could not read slaves JSON configuration file " + mApp.SlavesConfigFile + " --> " + err.Error())
	}
	//check error on defer log the error
	defer func() {
		err := configFile.Close()
		if err != nil {
			mApp.InfoLog.Println(err)
		}
	}()
	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&slaves)
	if err != nil {
		return errors.New("Error parsing slaves JSON file " + mApp.SlavesConfigFile + " --> " + err.Error())
	}
	//prepare Slaves array
	mApp.Slaves = slaves
	//Prepare Slaves hash map
	tempSlavesHashMap := map[string]SingleSlaveConfig{}
	for _, slave := range slaves {
		tempSlavesHashMap[slave.Name] = slave
	}
	mApp.SlavesHashMap = tempSlavesHashMap
	mApp.InfoLog.Println("Finished reading " + mApp.SlavesConfigFile + " file successfully")

	return nil

}

// Reading the list of the IP addresses and subnets that needs to be blocked from blocked.conf file
// Propagate the list of the blocked
func (mApp *MasterAPP) LoadBlockedConf() error {
	blockedFile, err := os.Open(mApp.PermBlockedConfigFile)
	if err != nil {
		return errors.New("Could not read blocked IP addresses configuration file " + mApp.PermBlockedConfigFile + " --> " + err.Error())
	}
	defer func() {
		err := blockedFile.Close()
		if err != nil {
			mApp.InfoLog.Println(err)
		}
	}()

	// Read config file line by line and add them to the array and create array indexing hash map to ease the removal of the elements to the slice
	tempSlice := []string{}
	tempHashMap := map[string]int{}
	scanner := bufio.NewScanner(blockedFile)
	// Read line after line from the blocked file
	index := 0
	for scanner.Scan() {
		IP := scanner.Text()
		correctIP, err := helpers.IpChecker(IP)
		if err != nil {
			mApp.ErrorLog.Println(err)
		}
		tempSlice = append(tempSlice, *correctIP)
		tempHashMap[*correctIP] = index
		index++
	}
	mApp.PermBlockedIPsArray = tempSlice
	mApp.PermBlockedIPsHashMap = tempHashMap
	if err := scanner.Err(); err != nil {
		return errors.New("Error in parsing blocked IP addresses configuration file " + mApp.PermBlockedConfigFile + " --> " + err.Error())
	}
	mApp.InfoLog.Println("Finished reading " + mApp.PermBlockedConfigFile + " file successfully")
	return nil
}

// The LoadInternalConf function used to do the following:
// 1- generate the internal.conf file if does not exists
func (mApp *MasterAPP) LoadInternalConf() error {
	//Read the contents of the internal configuration file
	configFile, err := os.Open(mApp.InternalConfPath)
	if os.IsNotExist(err) {
		//The internal config file does not exists so it needs to be generated
		internalConf := InternalConfigJson{
			PullCounter: mApp.PullCounter,
			// PermBlockedIPsArray: mApp.PermBlockedIPsArray,
			CliBlockedIPsArray: []BlockedCliIP{},
		}
		newConfigFile, err := os.Create(mApp.InternalConfPath)
		defer func() {
			if err := newConfigFile.Close(); err != nil {
				mApp.ErrorLog.Fatal("Could create the internal.json config file" + mApp.InternalConfPath + " --> " + err.Error())
			}
		}()
		if err != nil {
			return errors.New("Cannot Create internal config file " + mApp.InternalConfPath + " --> " + err.Error())
		}
		//now the internal json configuration file created then we need to write json to it
		encoder := json.NewEncoder(newConfigFile)
		err = encoder.Encode(&internalConf)
		if err != nil {
			return errors.New("Cannot write json data to the internal config file " + mApp.InternalConfPath + " --> " + err.Error())
		}
		mApp.InfoLog.Println("Internal configuration file " + mApp.InternalConfPath + " has been created successfully")
		return nil
	}
	//the internal json configuration file exits and needs to be read
	tempInternalConfig := InternalConfigJson{}
	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&tempInternalConfig)
	if err != nil {
		return errors.New("Cannot parse internal config file " + mApp.InternalConfPath + " --> " + err.Error() + "\n Please consider checking the JSON format inside the internal configuration file or try to remove the file\n Warning: removing the file will lead to retransmit all the blocked IP addresses in the blocked.list and all the IP addresses and subnets added thought the CLI and the restful API will be gone in both master and slave nodes.")
	}
	mApp.PullCounter = tempInternalConfig.PullCounter
	mApp.CliBlockedIPsArray = tempInternalConfig.CliBlockedIPsArray

	//Create internal CLI hash MAP to ease the process of accessing elements of the CliBlockedIPsArray slice
	tempCliHashMap := map[string]int{}
	for index, value := range tempInternalConfig.CliBlockedIPsArray {
		tempCliHashMap[*(value.Src)] = index
	}
	mApp.CliBlockedIPsHashMap = tempCliHashMap
	// mApp.InfoLog.Println("Internal configuration file " + mApp.InternalConfPath + " has been read successfully")
	mApp.InfoLog.Println("Finished reading " + mApp.InternalConfPath + " file successfully")

	//Increase the Pull counter to publish the data in the configuration file to all the slaves
	//only if the input autoPropagate from the user is true
	if mApp.AutoPropagate {
		mApp.PullCounter++
		mApp.WriteInternalConf()
	}
	return nil
}

// WriteInternalConf function used rewrite the contents of the internal.json
func (mApp *MasterAPP) WriteInternalConf() error {
	internalConf := InternalConfigJson{
		PullCounter: mApp.PullCounter,
		// PermBlockedIPsArray: mApp.PermBlockedIPsArray,
		CliBlockedIPsArray: mApp.CliBlockedIPsArray,
	}
	jsonData, err := json.MarshalIndent(internalConf, "", "	")
	if err != nil {
		return errors.New("Cannot parse the data to be written to " + mApp.InternalConfPath + " --> " + err.Error())
	}
	file, err := os.Create(mApp.InternalConfPath)
	defer func() {
		if err := file.Close(); err != nil {
			mApp.ErrorLog.Fatal(err)
		}
	}()
	if err != nil {
		return errors.New("Cannot open the file " + mApp.InternalConfPath + " --> " + err.Error())
	}

	//Write the json data to the file
	_, err = file.Write(jsonData)
	if err != nil {
		return errors.New("Cannot write data to the file " + mApp.InternalConfPath + " --> " + err.Error())
	}
	return nil
}

//Remove the blocked IP address from both the array of Blocked.list or the internal array of blocked IP addresses using the CLI or restful API requests

func (mApp *MasterAPP) RemoveBlockedIP(IP string, incPC bool) error {
	//check if the IP address is correct
	correctIP, err := helpers.IpChecker(IP)
	if err != nil {
		return errors.New("Incorrect IP address provided " + IP)
	}

	//Remove the blocked IP address or the subnets from the permanently blocked list of IP addresses
	index, ok := mApp.PermBlockedIPsHashMap[*correctIP]
	if ok {
		if len(mApp.PermBlockedIPsArray) == 0 {
			return nil
		}
		if len(mApp.PermBlockedIPsArray) == 1 {
			mApp.PermBlockedIPsArray = []string{}
			mApp.PermBlockedIPsHashMap = map[string]int{}
			mApp.PullCounter++
			mApp.WriteInternalConf()
			return nil
		}
		lastElement := mApp.PermBlockedIPsArray[len(mApp.PermBlockedIPsArray)-1]
		mApp.PermBlockedIPsArray = helpers.RemoveAndResliceArrayMap(mApp.PermBlockedIPsArray, index)
		mApp.PermBlockedIPsHashMap[lastElement] = index
		delete(mApp.PermBlockedIPsHashMap, *correctIP)
		if incPC {
			mApp.PullCounter++
		}
		mApp.WriteInternalConf()

		return nil
	}
	// mApp.InfoLog.Println(*correctIP)

	//Remove the blocked IP address or the subnets from the CLI blocked list of IP addresses
	index, ok = mApp.CliBlockedIPsHashMap[*correctIP]
	if ok {

		if len(mApp.CliBlockedIPsArray) == 0 {
			return nil
		}
		if len(mApp.CliBlockedIPsArray) == 1 {
			mApp.CliBlockedIPsArray = []BlockedCliIP{}
			mApp.CliBlockedIPsHashMap = map[string]int{}
			mApp.PullCounter++
			mApp.WriteInternalConf()
			return nil
		}
		// mApp.InfoLog.Println("Begin testing section")
		lastElement := mApp.CliBlockedIPsArray[len(mApp.CliBlockedIPsArray)-1]
		mApp.CliBlockedIPsArray = helpers.RemoveAndResliceArrayMap(mApp.CliBlockedIPsArray, index)
		mApp.CliBlockedIPsHashMap[*(lastElement.Src)] = index
		delete(mApp.CliBlockedIPsHashMap, *correctIP)

		// mApp.InfoLog.Println("Ending testing section")

		if incPC {
			mApp.PullCounter++
		}
		mApp.WriteInternalConf()
		return nil
	}
	return errors.New("The IP address " + *correctIP + " is already not blocked")
}

func (mApp *MasterAPP) CliAddBlockedIP(IP string, timeout int) error {
	//check if the IP address is valid or not
	correctIP, err := helpers.IpChecker(IP)
	if err != nil {
		return err
	}
	//check if the IP address or subnet is already blocked permanently using blocked.list file
	if _, ok := mApp.PermBlockedIPsHashMap[*correctIP]; ok {
		return errors.New("The IP address " + *correctIP + " is already blocked permanently!!")
	}
	//check if the IP address is blocked before using the CLI or restful API
	if index, ok := mApp.CliBlockedIPsHashMap[*correctIP]; ok {
		//Reset timeout counter with the new one if exists
		if mApp.CliBlockedIPsArray[index].Timeout != nil && timeout != 0 {
			*mApp.CliBlockedIPsArray[index].Timeout = timeout
			mApp.PullCounter++
			mApp.WriteInternalConf()
			return errors.New("The IP address " + *correctIP + " is already blocked (resetting timeout value to the new one!!)")
		}
		//if user try to block IP address but it is already blocked without timeout
		if mApp.CliBlockedIPsArray[index].Timeout == nil {
			return errors.New("The IP address " + *correctIP + " is already blocked permanently!!")

		}

		return errors.New("The IP address " + *correctIP + " is already blocked!!")
	}
	//The IP address is not blocked, so blocking it
	instanceBlockedIP := BlockedCliIP{
		Src:     correctIP,
		Timeout: &timeout,
	}
	//check if the input timeout parameter is 0 to block the input forever
	if timeout == 0 {
		instanceBlockedIP.Timeout = nil
	}
	mApp.CliBlockedIPsArray = append(mApp.CliBlockedIPsArray, instanceBlockedIP)
	mApp.CliBlockedIPsHashMap[*correctIP] = len(mApp.CliBlockedIPsArray) - 1
	mApp.PullCounter++
	mApp.WriteInternalConf()

	return nil
}

func (mApp *MasterAPP) CliFlushBlocked() {
	mApp.CliBlockedIPsArray = []BlockedCliIP{}
	mApp.CliBlockedIPsHashMap = map[string]int{}
	mApp.PullCounter++
	mApp.WriteInternalConf()
}
