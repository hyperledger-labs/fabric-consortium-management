// Copyright 2009-2019 SAP SE or an SAP affiliate company. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"gateway/configtxlator"

	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	providersContext "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/orderer"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	sdkCommon "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/common"
)

var (
	port              string
	connectionProfile string
	userKey           string
	userCert          string
	org               string
	channelID         string
	chaincodeID       string
)

func init() {
	flag.StringVar(&port, "port", "8080", "The TCP port on which the gateway will run.")
	flag.StringVar(&connectionProfile, "profile", "connection-profile.yaml", "The Fabric connection profile.")
	flag.StringVar(&org, "org", "", "The Fabric organization name.")
	flag.StringVar(&channelID, "channel", "", "The channel ID on which the chaincode is running.")
	flag.StringVar(&chaincodeID, "chaincode", "management", "The chaincode ID of the chaincode.")
	flag.StringVar(&userKey, "key", "user.key", "The user's private key for calling the chaincode.")
	flag.StringVar(&userCert, "cert", "user.cert", "The user's public key for calling the chaincode.")
	flag.Parse()
	if org == "" {
		panic("parameter 'org' required")
	}
	if channelID == "" {
		panic("parameter 'channelID' required")
	}
}

func main() {
	sdk, err := fabsdk.New(config.FromFile(connectionProfile))
	if err != nil {
		panic(err)
	}
	defer sdk.Close()
	user, err := getUser(sdk)
	if err != nil {
		panic(err)
	}

	handler, err := NewHandler(sdk, org, user, channelID, chaincodeID)
	if err != nil {
		panic(err)
	}
	http.Handle("/", http.FileServer(http.Dir("../www")))
	http.HandleFunc("/chaincode/invoke", handler.Invoke)
	http.HandleFunc("/chaincode/query", handler.Query)
	http.HandleFunc("/chaincode/events", handler.Events)
	http.HandleFunc("/sign", handler.Sign)
	http.HandleFunc("/update", handler.Update)
	http.HandleFunc("/info", handler.Info)
	http.HandleFunc("/decode/update", handler.DecodeUpdate)

	fmt.Printf("\nserver running on http://localhost:%s\n\n", port)
	panic(http.ListenAndServe(":"+port, nil))
}

func getUser(sdk *fabsdk.FabricSDK) (msp.SigningIdentity, error) {
	key, err := ioutil.ReadFile(userKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", userKey, err)
	}
	cert, err := ioutil.ReadFile(userCert)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", userCert, err)
	}

	sdkCtx, err := sdk.Context()()
	if err != nil {
		return nil, fmt.Errorf("failed to get sdk context: %v", err)
	}
	im, ok := sdkCtx.IdentityManager(org)
	if !ok {
		return nil, fmt.Errorf("failed to get identity manager")
	}
	user, err := im.CreateSigningIdentity(msp.WithPrivateKey(key), msp.WithCert(cert))
	if err != nil {
		return nil, fmt.Errorf("failed to create signing identity: %v", err)
	}
	return user, nil
}

type Handler struct {
	SDK              *fabsdk.FabricSDK
	User             msp.SigningIdentity
	Channel          string
	Chaincode        string
	client           *channel.Client
	lClient          *ledger.Client
	eventSubscribers []*websocket.Conn
}

type call struct {
	Function string   `json:"function"`
	Args     []string `json:"args"`
}

func getMetadataFromBlock(block *common.Block, index common.BlockMetadataIndex) (*common.Metadata, error) {
	md := &common.Metadata{}
	err := proto.Unmarshal(block.Metadata.Metadata[index], md)
	if err != nil {
		return nil, err
	}
	return md, nil
}

func getLastConfigIndexFromBlock(blockBytes []byte) (uint64, error) {
	block := &common.Block{}
	proto.Unmarshal(blockBytes, block)
	md, err := getMetadataFromBlock(block, common.BlockMetadataIndex_LAST_CONFIG)
	if err != nil {
		return 0, err
	}
	lc := &common.LastConfig{}
	err = proto.Unmarshal(md.Value, lc)
	if err != nil {
		return 0, err
	}
	return lc.Index, nil
}

func (h *Handler) getChannelUpdateBlock(newOrg []byte) ([]byte, error) {
	orgDecoded, err := base64.StdEncoding.DecodeString(string(newOrg))
	if err != nil {
		fmt.Printf("new org configuration can not be decoded: %s", err)
		return nil, err
	}

	newOrgConfig := make(map[string]interface{})
	if err := json.Unmarshal(orgDecoded, &newOrgConfig); err != nil {
		fmt.Println("The newOrg config Unmarshal failed: ", err.Error())
		return nil, err
	}

	newOrgName := newOrgConfig["values"].(map[string]interface{})["MSP"].(map[string]interface{})["value"].(map[string]interface{})["config"].(map[string]interface{})["name"].(string)

	ledgerInfo, err := h.lClient.QueryInfo()
	if err != nil {
		fmt.Printf("QueryInfo return error: %s", err)
		return nil, err
	}

	currentBlock, err := h.lClient.QueryBlockByHash(ledgerInfo.BCI.CurrentBlockHash)
	if err != nil {
		fmt.Printf("QueryBlockByHash return error: %s", err)
		return nil, err
	}
	if currentBlock.Metadata == nil {
		fmt.Printf("QueryBlockByHash block data is nil")
		return nil, err
	}

	b, err := proto.Marshal(currentBlock)
	if err != nil {
		fmt.Printf("Can not marshal current block.")
		return nil, err
	}

	lc, err := getLastConfigIndexFromBlock(b)
	if err != nil {
		fmt.Printf("GetLastConfigIndexFromBlock err: %s", err)
		return nil, err
	}

	lastBlock, err := h.lClient.QueryBlock(lc)
	if err != nil {
		fmt.Printf("Query Last Block err: %s", err)
	}
	b, err = proto.Marshal(lastBlock)
	if err != nil {
		fmt.Printf("Can not marshal last block.")
		return nil, err
	}

	channelGroup, err := configtxlator.DecodeProto("common.Block", b)
	if err != nil {
		fmt.Printf("Can not decode the common block %s", err)
		return nil, err
	}
	channelGroupOri, _ := configtxlator.DecodeProto("common.Block", b)

	channelGroup["channel_group"].(map[string]interface{})["groups"].(map[string]interface{})["Application"].(map[string]interface{})["groups"].(map[string]interface{})[newOrgName] = newOrgConfig

	oriBuffer := configtxlator.EncodeAndReplaceNull(channelGroupOri)
	updatedBuffer := configtxlator.EncodeAndReplaceNull(channelGroup)

	originalProtoBytes, err := configtxlator.EncodeProto("common.Config", oriBuffer.Bytes())
	if err != nil {
		fmt.Printf("Can not encode the original common block %s", err)
		return nil, err
	}

	newProtoBytes, err := configtxlator.EncodeProto("common.Config", updatedBuffer.Bytes())
	if err != nil {
		fmt.Printf("Can not encode the new common block %s", err)
		return nil, err
	}

	computeUpdateBytes, err := configtxlator.ComputeUpdt(originalProtoBytes, newProtoBytes, h.Channel)
	if err != nil {
		fmt.Printf("Can not compute the channel update common block %s", err)
		return nil, err
	}

	updateEncoded := base64.StdEncoding.EncodeToString(computeUpdateBytes)
	return []byte(updateEncoded), nil
}

func (h *Handler) Invoke(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to read body: %v", err)
		return
	}
	var c call
	if err := json.Unmarshal(body, &c); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to decode body: %v", err)
		return
	}
	args := make([][]byte, len(c.Args))
	for i, a := range c.Args {
		args[i] = []byte(a)
	}

	if c.Function == "proposeUpdate" {
		configBlockBytes, err := h.getChannelUpdateBlock(args[1])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "failed to make up the channel update block: %v", err)
			return
		}
		args[1] = configBlockBytes
	}

	resp, err := h.client.Execute(channel.Request{
		ChaincodeID: h.Chaincode,
		Fcn:         c.Function,
		Args:        args,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to query: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp.Payload)
}

func (h *Handler) Query(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to read body: %v", err)
		return
	}
	var c call
	if err := json.Unmarshal(body, &c); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to decode body: %v", err)
		return
	}
	args := make([][]byte, len(c.Args))
	for i, a := range c.Args {
		args[i] = []byte(a)
	}
	resp, err := h.client.Query(channel.Request{
		ChaincodeID: h.Chaincode,
		Fcn:         c.Function,
		Args:        args,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to query: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp.Payload)
}

var upgrader = websocket.Upgrader{
	HandshakeTimeout: 10 * time.Second,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (h *Handler) serveEvents() {
	reg, notifier, err := h.client.RegisterChaincodeEvent(h.Chaincode, ".*")
	if err != nil {
		panic(err)
	}
	defer h.client.UnregisterChaincodeEvent(reg)

	for ev := range notifier {
		payload, err := json.Marshal(&struct {
			Name    string `json:"name"`
			Payload string `json:"payload"`
		}{
			Name:    ev.EventName,
			Payload: string(ev.Payload),
		})
		if err != nil {
			fmt.Printf("failed to encode event%v\n", err)
			continue
		}
		// TODO events sometimes take very long because of lots of dead connections
		// send event to all subscribers
		for i := 0; i < len(h.eventSubscribers); i++ {
			conn := h.eventSubscribers[i]
			if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				closeWebSocket(conn, err.Error())
				h.eventSubscribers = append(h.eventSubscribers[:i], h.eventSubscribers[i+1:]...)
				i--
				continue
			}
		}
	}
}

func (h *Handler) Events(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "could not upgrade connection: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.eventSubscribers = append(h.eventSubscribers, conn)
}

func closeWebSocket(conn *websocket.Conn, msg string) {
	if err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, msg)); err != nil {
		// write: broken pipe -- most probably the client terminated the connection without calling close
		if !strings.Contains(err.Error(), "write: broken pipe") {
			fmt.Printf("ConnectEventStream failed to send close: %v\n", err)
		}
	}
	time.Sleep(5 * time.Second)
	if err := conn.Close(); err != nil {
		fmt.Printf("ConnectEventStream failed to close connection: %v\n", err)
	}
}
func (h *Handler) Info(w http.ResponseWriter, r *http.Request) {
	resp, err := json.Marshal(&struct {
		Org     string `json:"org"`
		Channel string `json:"channel"`
	}{
		Org:     org,
		Channel: channelID,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to encode response: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func (h *Handler) Sign(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to read body: %v", err)
		return
	}
	var req struct {
		ID     string `json:"id"`
		Update string `json:"update"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to decode body: %v", err)
		return
	}
	if len(req.Update) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "update missing")
		return
	}
	update, err := base64.StdEncoding.DecodeString(req.Update)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to read update: %v", err)
		return
	}
	sdkClient, err := h.SDK.Context(fabsdk.WithIdentity(h.User))()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to create sdk client: %v", err)
		return
	}
	signature, err := resource.CreateConfigSignature(sdkClient, update)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to create config signature: %v", err)
		return
	}
	sigBytes, err := proto.Marshal(signature)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to encode signature: %v", err)
		return
	}

	// send the signature to the chaincode
	resp, err := h.client.Execute(channel.Request{
		ChaincodeID: h.Chaincode,
		Fcn:         "addSignature",
		Args:        [][]byte{[]byte(req.ID), []byte(base64.StdEncoding.EncodeToString(sigBytes))},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to invoke: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp.Payload)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to read body: %v", err)
		return
	}
	var req struct {
		Update     string            `json:"update"`
		Signatures map[string]string `json:"signatures"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to decode body: %v", err)
		return
	}
	update, err := base64.StdEncoding.DecodeString(string(req.Update))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to read update: %v", err)
		return
	}

	contextClient, err := h.SDK.Context(fabsdk.WithIdentity(h.User))()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to get signing user: %v", err)
		return
	}

	orderers := contextClient.EndpointConfig().ChannelOrderers(h.Channel)
	if len(orderers) == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to get channel orderer: empty")
		return
	}
	ordererConfig := orderers[0]

	ordererTarget, err := orderer.New(contextClient.EndpointConfig(), orderer.FromOrdererConfig(&ordererConfig))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to get orderer: %v", err)
		return
	}

	ordererContext, ordrReqCtxCancel := context.NewRequest(contextClient, context.WithTimeout(15*time.Second))
	defer ordrReqCtxCancel()

	updateenvelope, err := generateUpdateEnvelope(update)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to generate update envelope: %v", err)
		return
	}

	// parse the signatures
	var updateChannelSignatures []*sdkCommon.ConfigSignature
	for _, configUpdateSignatureB64 := range req.Signatures {
		configUpdateSignatureSerialized, err := base64.StdEncoding.DecodeString(configUpdateSignatureB64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "failed to base64 decode signature: %v", err)
			return
		}
		configUpdateSignature := &sdkCommon.ConfigSignature{}
		if err := proto.Unmarshal(configUpdateSignatureSerialized, configUpdateSignature); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "failed to decode signature to proto: %v", err)
			return
		}
		updateChannelSignatures = append(updateChannelSignatures, configUpdateSignature)
	}

	chConfig, configSignatures, err := generateChannelUpdate(contextClient, updateenvelope, updateChannelSignatures)

	_, err = resource.CreateChannel(ordererContext, resource.CreateChannelRequest{
		Name:       channelID,
		Orderer:    ordererTarget,
		Config:     chConfig,
		Signatures: configSignatures,
	})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to update channel: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func generateUpdateEnvelope(channelUpdateSerialized []byte) ([]byte, error) {
	// check input
	if err := proto.Unmarshal(channelUpdateSerialized, &common.ConfigUpdate{}); err != nil {
		return nil, fmt.Errorf("error marshalling ConfigUpdate: %v", err)
	}

	// wrap input for client.ExtractChannelConfig
	configEnvelope := &common.ConfigUpdateEnvelope{
		ConfigUpdate: channelUpdateSerialized,
	}
	configEnvelopeSerialized, err := proto.Marshal(configEnvelope)
	if err != nil {
		return nil, fmt.Errorf("error marshalling configEnvelope: %v", err)
	}

	payload := &common.Payload{
		Data: configEnvelopeSerialized,
	}

	payloadSerialized, err := proto.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %v", err)
	}

	channelUpdateEnvelope := &common.Envelope{
		Payload: payloadSerialized,
	}
	channelUpdateEnvelopeSerialized, err := proto.Marshal(channelUpdateEnvelope)
	if err != nil {
		return nil, fmt.Errorf("error marshalling channelUpdateEnvelope: %v", err)
	}
	return channelUpdateEnvelopeSerialized, nil
}

func generateChannelUpdate(client providersContext.Client, channelTxConfigEnvelope []byte, configSignatures []*sdkCommon.ConfigSignature) ([]byte, []*sdkCommon.ConfigSignature, error) {
	chConfig, err := resource.ExtractChannelConfig(channelTxConfigEnvelope)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract channel config: %v", err)
	}
	signature, err := resource.CreateConfigSignature(client, chConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign configuration: %v", err)
	}
	configSignatures = append(configSignatures, signature)

	return chConfig, configSignatures, nil
}

func (h *Handler) DecodeUpdate(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to read body: %v", err)
		return
	}
	b64, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to read update: %v", err)
		return
	}
	var update common.ConfigUpdate
	if err := proto.Unmarshal(b64, &update); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failed to decode update: %v", err)
		return
	}

	resp, err := json.Marshal(&update)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to encode response: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func NewHandler(sdk *fabsdk.FabricSDK, org string, user msp.SigningIdentity, channelID, chaincodeID string) (*Handler, error) {
	clientContext := sdk.ChannelContext(channelID, fabsdk.WithIdentity(user), fabsdk.WithOrg(org))
	channelClient, err := channel.New(clientContext)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel client: %v", err)
	}
	ledgerClient, err := ledger.New(clientContext)
	if err != nil {
		return nil, fmt.Errorf("failed to create ledger client: %v", err)
	}

	h := &Handler{
		SDK:       sdk,
		User:      user,
		Channel:   channelID,
		Chaincode: chaincodeID,
		client:    channelClient,
		lClient:   ledgerClient,
	}
	go h.serveEvents()
	return h, nil
}
