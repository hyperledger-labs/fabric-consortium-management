# Dockerfile for hyperledger cello ansible agent
#
# @see https://github.com/hyperledger/cello/blob/master/docs/worker_ansible_howto.md
#
FROM golang AS BUILD

RUN mkdir -p /opt/build
COPY gateway /opt/build
RUN cd /opt/build && export GO111MODULE=on && go build

FROM alpine
MAINTAINER Tong Li <litong01@us.ibm.com>
RUN mkdir /cmcc && mkdir /www && apk add --no-cache libc6-compat
COPY --from=build /opt/build/gateway /usr/local/bin/gateway
COPY www /www
ENV HOME=/cmcc \
    WORKDIR=/cmcc \
    profile=/cmcc/connection-profile.yaml \
    port=8080 \
    key=user.key \
    cert=user.cert

WORKDIR /cmcc
ENTRYPOINT gateway -org=$org -port=$port -profile=$profile -channel=$channel -chaincode=$chaincode -key=$key -cert=$cert
