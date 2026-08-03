

# Tabla de contenidos

- [Introducción](#introduction)
- [Primeros Pasos](#quick-start)
  - [Primeros Pasos para GoXDP en Docker](#quick-start-for-goxdp-on-docker)
  - [Primeros Pasos para el binario de GoXDP](#quick-start-for-goxdp-binary)
  - [Primeros Pasos para la configuración Maestro-Esclavo de GoXDP](#quick-start-for-goxdp-master-slave-setup)
- [Servicio GoXDP](#goxdp-service)
- [Servicio Maestro GoXDP](#goxdp-master-service)
- [Cliente GoXDP](#goxdp-client)
- [Cliente API RestFull](#restfull-api-client)

# Introducción

GoXDP es un filtro XDP simple y potente con código de espacio de kernel construido en C y código de espacio de usuario construido en Golang que utiliza el poder del algoritmo de coincidencia de prefijo más largo (LPM) para filtrar subredes y direcciones IP con tiempos de espera predefinidos. Además, la interacción con GoXDP puede realizarse a través de la RestfulAPI o los comandos del cliente CLI. <br>
![golang-logo](assets/golang-logo.png)

# Primeros Pasos

## Primeros Pasos para GoXDP en Docker

`docker run -d --network host --name goxdp --privileged --restart always ahsifer/goxdp:2.1 server -privateIP=127.0.0.1`

## Primeros Pasos para el binario de GoXDP

- Descarga el último binario desde https://github.com/ahsifer/goxdp/releases.
- Ejecuta `goxdp server -privateIP=127.0.0.1` para iniciar el servicio goxdp.

## Primeros Pasos para la configuración Maestro-Esclavo de GoXDP

1. Inicia el servicio maestro (Los archivos auth.json y blocked.list deben crearse primero como se muestra en la [wiki Maestro-Esclavo](assets/Master-Slave.md)) <br>
   `docker run -d --network host --name goxdp-master -v /etc/goxdp/:/etc/goxdp/:rw -v /etc/localtime:/etc/localtime:ro --restart always ahsifer/goxdp:3.0 master -blockedFilePath=/etc/goxdp/blocked.list -authConfPath=/etc/goxdp/auth.json -certFilePath=/etc/goxdp/cert.pem -keyFilePath=/etc/goxdp/key.pem -internalConfPath=/etc/goxdp/internal.json  -timeoutCheckerInterval=5`
2. Inicia el servicio esclavo <br>
   `docker run -d --network host --name goxdp-slave --privileged --restart always -v /etc/localtime:/etc/localtime:ro ahsifer/goxdp:3.0 server --master=true --masterIP=127.0.0.1 --masterPort=9999 --validSSL=false --masterPullInterval=5 --protocol=https --timeoutInterval=5`

# Servicio GoXDP

Lo siguiente incluye los argumentos de línea de comandos disponibles y sus descripciones al iniciar un nuevo servicio GoXDP:

```
./goxdp server -h
Usage of server:
  -privateIP string
    	The private IP address the service will listen to, that will be used to respond to load,unload,block,allow, and status requests (default "127.0.0.1")
  -privatePort string
    	The private Port number the service will listen to (default "8090")
  -publicIP string
    	The public IP address the service will listen to that will be used to respond to metrics and status requests (default "127.0.0.1")
  -publicPort string
    	The public Port number the service will listen to (default "8091")
  -timeoutInterval int
    	The timeout interval of the worker thread to check if subnet or IP address timeout is finished (default 30)
  -master
    	Enable master-slave communication
  -masterIP string
    	The IP address of the master service (default "127.0.0.1")
  -masterPort string
    	The port number that the master service is listening to (default "9999")
  -protocol string
    	use http or https to communicate with the master (default "http")
  -validSSL
    	Enable when the master uses valid SSL certificate (useful when the chosen protocol is https)
  -masterPullInterval int
    	The timeout interval between checking for updates from the master (default 5)

```

# Servicio Maestro GoXDP

Lo siguiente incluye los argumentos de línea de comandos disponibles y sus descripciones al iniciar un nuevo servicio maestro GoXDP:

```
./goxdp master -h
Usage of master:
  -IP string
    	The IP address the master service will listen to (default "0.0.0.0")
  -Port string
    	The Port number the master service will listen to (default "8090")
  -authConfPath string
    	Path to the authentication config file (default "/etc/goxdp/auth.json")
  -blockedFilePath string
    	Path to the file that include the initial IP addresses and subnets that needs to be blocked in all the slaves once the master service starts (default "/etc/goxdp/blocked.list")
  -internalConfPath string
    	Path to the auto generated file that used to store the information about all the blocked IP addresses and subnets that have been added using CLI or restful API to keep them permanent after restarts (default "/etc/goxdp/internal.json")
  -autoPropagate
    	Retransmit the blocked IP addresses to all the slaves when master starts or restart (Increment the PULL_COUNTER on restarts) (default false)
  -enableSSl
    	Enable SSL on Master communication (default true)
  -certFilePath string
    	Path to certificate file (default "/etc/goxdp/cert.pem")
  -keyFilePath string
    	Path to key file (default "/etc/goxdp/key.pem")

  -timeoutCheckerInterval int
    	The timeout interval in seconds that the master service will check if the timeout of blocked IP address or subnets is finished (default 5)
```

Para más información visite la [wiki Maestro-Esclavo](assets/Master-Slave.md)

# Cliente GoXDP

Se pueden seguir dos enfoques diferentes para interactuar con XDP: <br />
1- Usando el cliente CLI de GoXDP <br />
2- Usando la API RestFul <br />

## Cliente CLI de GoXDP

El primer enfoque presenta los comandos CLI del cliente GoXDP para realizar operaciones de carga, descarga, bloqueo, desbloqueo y estado. Los argumentos disponibles son:

```
./goxdp client -h
Usage of client:
  -action string
    	Available values are load,unload,block, allow, status (Also incremental and reload can be used with the master service)
  -dstIP string
    	The IP address that the goxdp service is listening to (default "127.0.0.1")
  -dstPort string
    	The Port that the goxdp service is listening to (default "8090")
  -flush
    	Passed alongside with the actions status,block,allow to flush the status or blocked IP addresses or subnets tables
  -interfaces string
    	Interfaces names that the XDP programme will be loaded to (Example 'eth0,eth1')
  -mode string
    	The mode that XDP programme will be loaded (available modes are nv,skb, and hw)
  -src string
    	src IP address or subnet that will be blocked or allowed
  -timeout uint
    	How long the IP address or the subnet will be blocked in seconds
  -master
    	Destination host is a master or not (default false)
  -protocol string
    	use http or https (Useful when the master service using HTTPS) (default "http")
  -validSSL
    	Validate destination certificate when protocol parameter is true (Useful when the master service is using valid certificate) (default false)
  -username string
    	Used for authentication purposes when contacting the master service
  -token string
    	Used for authentication purposes when contacting the master service
```

## Operaciones CLI:

> Nota: todas las siguientes operaciones se pueden usar con el servicio maestro, solo se necesitan agregar los siguientes parámetros <br>
> 1- master <br>
> 2- protocol <br>
> 3- validSSl <br>
> 4- username <br>
> 5- token <br>

> Nota: Solo load y unload no se pueden usar con el servicio maestro

### 1- Cargar filtro XDP a la interfaz <br />

Cargar el filtro XDP a una sola interfaz

```
goxdp client --action=load --interfaces=eth0 --mode=skb --dstIP=127.0.0.1 --dstPort=8090
```

Cargar filtro XDP a múltiples interfaces

```
goxdp client --action=load --interfaces=eth0,eth1 --mode=skb --dstIP=127.0.0.1 --dstPort=8090
```

### 2- Descargar el filtro de la interfaz<br />

Descargar el filtro XDP de una sola interfaz

```
goxdp client --action=unload --interfaces=eth0 --dstIP=127.0.0.1 --dstPort=8090
```

Descargar el filtro XDP de múltiples interfaces

```
goxdp client --action=unload --interfaces=eth0,eth1 --dstIP=127.0.0.1 --dstPort=8090
```

Descargar el filtro XDP de todas las interfaces

```
goxdp client --action=unload --interfaces=all --dstIP=127.0.0.1 --dstPort=8090
```

### 3- Bloquear una dirección IP o subred

bloquear 10.4.4.0/24 por 100 segundos

```
goxdp client --action=block --src=10.4.4.0/24 --timeout=100 --dstIP=127.0.0.1 --dstPort=8090
```

bloquear 10.4.4.0/24 para siempre

```
goxdp client --action=block --src=10.4.4.0/24 --timeout=0 --dstIP=127.0.0.1 --dstPort=8090
```

> Nota: Puede bloquear una sola dirección IP pasando 10.4.4.4 o 10.4.4.4/32.

<br />

> Nota: Bloquear la misma dirección IP o subred más de una vez solo cambia el valor del tiempo de espera.

### 4- Desbloquear una dirección IP o subred

```
goxdp client --action=allow --src=10.4.4.0/24 --dstIP=127.0.0.1 --dstPort=8090
```

### 5- Desbloquear todas las direcciones IP y subredes

```
goxdp client --action=block --flush --dstIP=127.0.0.1 --dstPort=8090
```

### 6- Mostrar estado

```
goxdp client --action=status --dstIP=127.0.0.1 --dstPort=8090
```

o

```
goxdp client --action=status --dstIP=127.0.0.1 --dstPort=8091
```

### 7- Vaciar tabla de estado

```
goxdp client --action=status --flush --dstIP=127.0.0.1 --dstPort=8090
```

### 8- Incrementar el contador de extracción del maestro

```
goxdp client --action=increment --dstIP=127.0.0.1 --dstPort=9999 --master=true --protocol=https --validSSL=false --username=xxxx --token=xxxx
```

### 9- Recargar los archivos de configuración del maestro (reevaluar internal.json, blocked.list y auth.json)

```
goxdp client --action=reload --dstIP=127.0.0.1 --dstPort=9999 --master=true --protocol=https --validSSL=false --username=xxxx --token=xxxx
```

## Cliente API RestFull

> Nota: todas las siguientes solicitudes http se pueden usar con el servicio maestro (excepto load y unload), solo se necesitan agregar las siguientes dos cabeceras <br>
> 1- username <br>
> 2- token <br>

### 1- POST: Cargar filtro XDP a la interfaz

```
curl -X POST http://127.0.0.1:8090/load -d '{"interfaces":"eth0","mode":"skb"}'
```

### 2- POST: Descargar filtro XDP

```
curl -X POST http://127.0.0.1:8090/unload -d '{"interfaces":"eth0"}'
```

### 3- POST: Bloquear una dirección IP o subred

```
curl -X POST http://127.0.0.1:8090/block -d '{"src":"127.0.0.2/32","action":"block","timeout":500}'
```

### 4- POST: Desbloquear una dirección IP o subred

```
curl -X POST http://127.0.0.1:8090/block -d '{"src":"127.0.0.2/32","action":"allow","timeout":500}'
```

### 5- POST: Desbloquear todas las direcciones IP y subredes

```
curl -X POST http://127.0.0.1:8090/flushblocked
```

### 6- GET: mostrar estado

```
curl -X GET http://127.0.0.1:8090/status | jq .
```

o

```
curl -X GET http://127.0.0.1:8091/status | jq .
```

### 7- POST: vaciar tabla de estado

```
curl -X GET http://127.0.0.1:8090/flushstatus
```

### 8- POST: Incrementar el contador de extracción del maestro

```
curl -X POST -k --header "username:xxxx" --header "token:xxxx" https://127.0.0.1:9999/increment
```

### 9- POST: recargar configuración del maestro

```
curl -X POST -k --header "username:xxxx" --header "token:xxxx" https://127.0.0.1:9999/reload
```

# Métricas

El siguiente extremo se utiliza para obtener métricas sobre el servicio GoXDP

```
curl -X GET http://127.0.0.1:8091/metrics
```
