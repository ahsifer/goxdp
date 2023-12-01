# Introduction

GoXDP is a simple and powerful XDP filter with kernel-space code built with C and user-space code built with Golang that utilizes the power of the longest prefix matching (LPM) algorithm to filter subnets and IP addresses with predefined timeouts. Also, interacting with GoXDP can be through the RestfulAPI or the CLI client commands.
![golang-logo](golang-logo.png)

# Quick Start

## Quick Start for GoXDP on Docker

`docker run -d --network host --name goxdp --privileged --restart always ahsifer/goxdp:2.1 server -privateIP=127.0.0.1`

## Quick Start for GoXDP binary

- Download the latest binary from the repository.
- Run `goxdp server -privateIP=127.0.0.1` to start goxdp service.

# GoXDP service

The following include the available command line arguments and their description when starting a new GoXDP service:

```
goxdp server -h
Usage of server:
  -privateIP string
    	The private IP address the service will listen to, that will be used to respond to load,unload,block,allow, and status requests (default "127.0.0.1")
  -privatePort string
    	The private Port number the service will listen to (default "8090")
  -publicIP string
    	The public IP address the service will listen to, that will be used to respond to metrics and status requests (default "127.0.0.1")
  -publicPort string
    	The public Port number the service will listen to (default "8091")
  -timeoutinterval int
    	How long the timeout checker thread will wait before checking if there is any IP address or subnet with finished timeout to remove them from the blocked list.
```

# GoXDP Client

Two different approaches can be followed to interact with XDP: <br />
1- Using GoXDP CLI client <br />
2- Using RestFul API <br />

## GoXDP CLI Client

The first approach introduces the GoXDP client CLI commands to perform load, unload, block, unblock, and status operations. The available arguments are:

```
./goxdp client -h
Usage of client:
  -action string
    	Available values are load,unload,block, allow, status
  -dstIP string
    	The IP address that the goxdp service is listening to (default "127.0.0.1")
  -dstPort string
    	The Port that the goxdp service is listening to (default "8090")
  -interfaces string
    	Interfaces names that the XDP programme will be loaded or unloaded (Example 'eth0,eth1')
  -mode string
    	The mode that XDP programme will be loaded (available values are nv,skb, and hw)
  -src string
    	src IP address or subnet that will be blocked or allowed
  -timeout uint
    	How long the IP address or the subnet will be blocked in seconds
```

**CLI Operations:**

### 1- Load XDP filter to interface <br />

Load the XDP filter to a single interface

```
goxdp client --action=load --interfaces=eth0 --mode=skb --dstIP=127.0.0.1 --dstPort=8090
```

Load XDP filter to multiple interfaces

```
goxdp client --action=load --interfaces=eth0,eth1 --mode=skb --dstIP=127.0.0.1 --dstPort=8090
```

### 2- Unload the filter from the interface<br />

Unload the XDP filter from a single interface

```
goxdp client --action=unload --interfaces=eth0 --dstIP=127.0.0.1 --dstPort=8090
```

Unload the XDP filter from multiple interfaces

```
goxdp client --action=unload --interfaces=eth0,eth1 --dstIP=127.0.0.1 --dstPort=8090
```

Unload the XDP filter from all the interfaces

```
goxdp client --action=unload --interfaces=all --dstIP=127.0.0.1 --dstPort=8090
```

### 3- block an IP address or subnet

block 10.4.4.0/24 for 100 seconds

```
goxdp client --action=block --src=10.4.4.0/24 --timeout=100 --dstIP=127.0.0.1 --dstPort=8090
```

block 10.4.4.0/24 forever

```
goxdp client --action=block --src=10.4.4.0/24 --timeout=0 --dstIP=127.0.0.1 --dstPort=8090
```

> Note: You can block a single IP address by passing 10.4.4.4 or 10.4.4.4/32.

<br />

> Note: Blocking the same IP address or subnet more than once just changes the timeout value.

### 4- unblock an IP address or subnet

```
goxdp client --action=allow --src=10.4.4.0/24 --dstIP=127.0.0.1 --dstPort=8090
```

### 5- unblock all the IP addresses and subnets

```
goxdp client --action=block --flush --dstIP=127.0.0.1 --dstPort=8090
```

### 6- Show status

```
goxdp client --action=status --dstIP=127.0.0.1 --dstPort=8090
```

or

```
goxdp client --action=status --dstIP=127.0.0.1 --dstPort=8091
```

### 6- empty status table

```
goxdp client --action=status --flush --dstIP=127.0.0.1 --dstPort=8090
```

## RestFull API Client

The second approach to interact with GoXDP is using the GET and POST request to the restful endpoints: <br />

### 1- POST: Load XDP filter to interface

```
curl -X POST http://127.0.0.1:8090/load -d '{"interfaces":"eth0","mode":"skb"}'
```

### 2- POST: Unload XDP filter

```
curl -X POST http://127.0.0.1:8090/unload -d '{"interfaces":"eth0"}'
```

### 3- POST: Block an IP address or subnet

```
curl -X POST http://127.0.0.1:8090/block -d '{"src":"127.0.0.2/32","action":"block","timeout":500}'
```

### 4- POST: Unblock an IP address or subnet

```
curl -X POST http://127.0.0.1:8090/block -d '{"src":"127.0.0.2/32","action":"allow","timeout":500}'
```

### 5- POST: Unblock all the IP addresses and subnets

```
curl -X POST http://127.0.0.1:8090/flushblocked
```

### 6- GET: show status

```
curl -X GET http://127.0.0.1:8090/status | jq .
```

or

```
curl -X GET http://127.0.0.1:8091/status | jq .
```

### 7- POST: empty status table

```
curl -X GET http://127.0.0.1:8090/flushstatus
```

# Metrics

The following endpoint is used to fetch metrics about the GoXDP service

```
curl -X GET http://127.0.0.1:8091/metrics
```
