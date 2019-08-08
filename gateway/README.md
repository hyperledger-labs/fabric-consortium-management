# Management Dashboard Gateway


## Prerequisites

* Minimum Go v1.11 compiler
* Fabric connection profile (recommended default named file: `connection-profile.yaml`) 
* User credentials (recommended default named files: `user.key` and `user.cert`)
* Fabric organization
* Fabric channel ID
* Chaincode ID


## Building Gateway

```bash
Mac:
export GO111MODULE=on
go build

Windows:
set GO111MODULE=on
go build
```


## Running Gateway

```bash
Mac:
./gateway -org=<organization-id> -channel=<channel-id> -chaincode=<chaincode-id>

Windows:
gateway -org=<organization-id>   -channel=<channel-id> -chaincode=<chaincode-id>
```



## Command-Line Parameters

```bash
Usage of gateway:
  -cert string
        The user's public key for calling the chaincode. (default "user.cert")
  -chaincode string
        The chaincode ID of the chaincode. (default "management")
  -channel string
        The channel ID on which the chaincode is running.
  -key string
        The user's private key for calling the chaincode. (default "user.key")
  -org string
        The Fabric organization name.
  -port string
        The TCP port on which the gateway will run. (default "8080")
  -profile string
        The Fabric connection profile. (default "connection-profile.yaml")
```

