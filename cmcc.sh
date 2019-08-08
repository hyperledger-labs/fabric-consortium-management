#!/bin/bash
#
# Usage: ./cmcc.sh orgName port channel_name chaincode_name
#   For example: ./cmcc.sh org0 8080 interopchannel0  cmcc0
#
docker run -d -v $(pwd)/keyfiles/$1:/cmcc \
  -v $(pwd)/keyfiles:/fabric/keyfiles \
  -e org=$1 -e profile=/cmcc/connection.yml \
  -e channel=$3 -e chaincode=$4 -e port=8080 \
  -e cert=/cmcc/users/Admin@$1/msp/admincerts/Admin@$1-cert.pem \
  -e key=/cmcc/users/Admin@$1/msp/keystore/admin_private.key \
  -p $2:8080  --name cli$1 cmcc:latest
