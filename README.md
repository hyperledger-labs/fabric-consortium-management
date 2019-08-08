# Management Dashboard Gateway

1. Clone everything from this repo

```
   git clone https://github.com/litong01/fabinterop.git
```

2. Build the docker image file by using the following command:

```
   docker build -t cmcc:latest .
```

3. Once you have the docker image, use the following command to start an instance

```
   ./cmcc.sh <orgname> <port> <channelname> <chaincodename>

   For example,
     to start instance for org0 at port 8080, do the following:
      ./cmcc.sh org0 8080 interopchannel0 cmcc0
     to start instance for org1 at port 9090, do the following:
      ./cmcc.sh org1 9090 interopchannel0 cmcc0

The above assume that your key files organized like the following:
    ./keyfiles/org0/users/Admin@org0/msp/admincerts/Admin@org0-cert.pem
    ./keyfiles/org0/users/Admin@org0/msp/keystore/admin_private.key
    ./keyfiles/org0/connection.yml
    ./keyfiles/org1/users/Admin@org1/msp/admincerts/Admin@org1-cert.pem
    ./keyfiles/org1/users/Admin@org1/msp/keystore/admin_private.key
    ./keyfiles/org1/connection.yml
```
