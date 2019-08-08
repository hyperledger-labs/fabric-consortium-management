/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package configtxlator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"

	"io/ioutil"

	"gateway/protolator"

	cb "github.com/hyperledger/fabric/protos/common"
	_ "github.com/hyperledger/fabric/protos/msp"
	_ "github.com/hyperledger/fabric/protos/orderer"
	_ "github.com/hyperledger/fabric/protos/peer"
)

// QueryChannelConfig used to query latest channel config block
func DecodeProto(msgName string, configBytes []byte) (map[string]interface{}, error) {
	msgType := proto.MessageType(msgName)
	if msgType == nil {
		return nil, errors.Errorf("message of type %s unknown", msgType)
	}
	msg := reflect.New(msgType.Elem()).Interface().(proto.Message)

	err := proto.Unmarshal(configBytes, msg)
	if err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling")
	}

	var buffer bytes.Buffer
	err = protolator.DeepMarshalJSON(&buffer, msg)
	if err != nil {
		return nil, errors.Wrapf(err, "error decoding output")
	}

	configJson := make(map[string]interface{})
	err = json.Unmarshal(buffer.Bytes(), &configJson)
	if err != nil {
		fmt.Printf("error in unmarshal bytes to json")
	}
	//fmt.Printf("configJSON is %s \n",configJson)
	if msgName == "common.Block" {
		channelGroup := configJson["data"].(map[string]interface{})["data"].([]interface{})[0].(map[string]interface{})["payload"].(map[string]interface{})["data"].(map[string]interface{})["config"].(map[string]interface{})
		return channelGroup, nil
	}

	return configJson, nil
}

// QueryChannelConfig used to query latest channel config block
func EncodeProto(msgName string, configBytes []byte) ([]byte, error) {
	msgType := proto.MessageType(msgName)
	if msgType == nil {
		return nil, errors.Errorf("message of type %s unknown", msgType)
	}
	msg := reflect.New(msgType.Elem()).Interface().(proto.Message)

	buffer := bytes.NewBuffer(configBytes)

	err := protolator.DeepUnmarshalJSON(buffer, msg)

	if err != nil {
		return nil, errors.Wrapf(err, "error encoding output")
	}

	out, err := proto.Marshal(msg)
	if err != nil {
		return nil, errors.Wrapf(err, "error marshaling")
	}
	return out, nil
}

// QueryChannelConfig used to query latest channel config block
func ComputeUpdt(origIn, updtIn []byte, channelID string) ([]byte, error) {
	origConf := &cb.Config{}
	err := proto.Unmarshal(origIn, origConf)
	if err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling original config")
	}

	updtConf := &cb.Config{}
	err = proto.Unmarshal(updtIn, updtConf)
	if err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling updated config")
	}

	cu, err := Compute(origConf, updtConf)
	if err != nil {
		return nil, errors.Wrapf(err, "error computing config update")
	}

	cu.ChannelId = channelID

	outBytes, err := proto.Marshal(cu)
	if err != nil {
		return nil, errors.Wrapf(err, "error marshaling computed config update")
	}

	return outBytes, nil
}

func computePoliciesMapUpdate(original, updated map[string]*cb.ConfigPolicy) (readSet, writeSet, sameSet map[string]*cb.ConfigPolicy, updatedMembers bool) {
	readSet = make(map[string]*cb.ConfigPolicy)
	writeSet = make(map[string]*cb.ConfigPolicy)

	// All modified config goes into the read/write sets, but in case the map membership changes, we retain the
	// config which was the same to add to the read/write sets
	sameSet = make(map[string]*cb.ConfigPolicy)

	for policyName, originalPolicy := range original {
		updatedPolicy, ok := updated[policyName]
		if !ok {
			updatedMembers = true
			continue
		}

		if originalPolicy.ModPolicy == updatedPolicy.ModPolicy && reflect.DeepEqual(originalPolicy.Policy, updatedPolicy.Policy) {
			sameSet[policyName] = &cb.ConfigPolicy{
				Version: originalPolicy.Version,
			}
			continue
		}

		writeSet[policyName] = &cb.ConfigPolicy{
			Version:   originalPolicy.Version + 1,
			ModPolicy: updatedPolicy.ModPolicy,
			Policy:    updatedPolicy.Policy,
		}
	}

	for policyName, updatedPolicy := range updated {
		if _, ok := original[policyName]; ok {
			// If the updatedPolicy is in the original set of policies, it was already handled
			continue
		}
		updatedMembers = true
		writeSet[policyName] = &cb.ConfigPolicy{
			Version:   0,
			ModPolicy: updatedPolicy.ModPolicy,
			Policy:    updatedPolicy.Policy,
		}
	}

	return
}

func computeValuesMapUpdate(original, updated map[string]*cb.ConfigValue) (readSet, writeSet, sameSet map[string]*cb.ConfigValue, updatedMembers bool) {
	readSet = make(map[string]*cb.ConfigValue)
	writeSet = make(map[string]*cb.ConfigValue)

	// All modified config goes into the read/write sets, but in case the map membership changes, we retain the
	// config which was the same to add to the read/write sets
	sameSet = make(map[string]*cb.ConfigValue)

	for valueName, originalValue := range original {
		updatedValue, ok := updated[valueName]
		if !ok {
			updatedMembers = true
			continue
		}

		if originalValue.ModPolicy == updatedValue.ModPolicy && reflect.DeepEqual(originalValue.Value, updatedValue.Value) {
			sameSet[valueName] = &cb.ConfigValue{
				Version: originalValue.Version,
			}
			continue
		}

		writeSet[valueName] = &cb.ConfigValue{
			Version:   originalValue.Version + 1,
			ModPolicy: updatedValue.ModPolicy,
			Value:     updatedValue.Value,
		}
	}

	for valueName, updatedValue := range updated {
		if _, ok := original[valueName]; ok {
			// If the updatedValue is in the original set of values, it was already handled
			continue
		}
		updatedMembers = true
		writeSet[valueName] = &cb.ConfigValue{
			Version:   0,
			ModPolicy: updatedValue.ModPolicy,
			Value:     updatedValue.Value,
		}
	}

	return
}

func computeGroupsMapUpdate(original, updated map[string]*cb.ConfigGroup) (readSet, writeSet, sameSet map[string]*cb.ConfigGroup, updatedMembers bool) {
	readSet = make(map[string]*cb.ConfigGroup)
	writeSet = make(map[string]*cb.ConfigGroup)

	// All modified config goes into the read/write sets, but in case the map membership changes, we retain the
	// config which was the same to add to the read/write sets
	sameSet = make(map[string]*cb.ConfigGroup)

	for groupName, originalGroup := range original {
		updatedGroup, ok := updated[groupName]
		if !ok {
			updatedMembers = true
			continue
		}

		groupReadSet, groupWriteSet, groupUpdated := computeGroupUpdate(originalGroup, updatedGroup)
		if !groupUpdated {
			sameSet[groupName] = groupReadSet
			continue
		}

		readSet[groupName] = groupReadSet
		writeSet[groupName] = groupWriteSet

	}

	for groupName, updatedGroup := range updated {
		if _, ok := original[groupName]; ok {
			// If the updatedGroup is in the original set of groups, it was already handled
			continue
		}
		updatedMembers = true
		_, groupWriteSet, _ := computeGroupUpdate(cb.NewConfigGroup(), updatedGroup)
		writeSet[groupName] = &cb.ConfigGroup{
			Version:   0,
			ModPolicy: updatedGroup.ModPolicy,
			Policies:  groupWriteSet.Policies,
			Values:    groupWriteSet.Values,
			Groups:    groupWriteSet.Groups,
		}
	}

	return
}

func computeGroupUpdate(original, updated *cb.ConfigGroup) (readSet, writeSet *cb.ConfigGroup, updatedGroup bool) {
	readSetPolicies, writeSetPolicies, sameSetPolicies, policiesMembersUpdated := computePoliciesMapUpdate(original.Policies, updated.Policies)
	readSetValues, writeSetValues, sameSetValues, valuesMembersUpdated := computeValuesMapUpdate(original.Values, updated.Values)
	readSetGroups, writeSetGroups, sameSetGroups, groupsMembersUpdated := computeGroupsMapUpdate(original.Groups, updated.Groups)

	// If the updated group is 'Equal' to the updated group (none of the members nor the mod policy changed)
	if !(policiesMembersUpdated || valuesMembersUpdated || groupsMembersUpdated || original.ModPolicy != updated.ModPolicy) {

		// If there were no modified entries in any of the policies/values/groups maps
		if len(readSetPolicies) == 0 &&
			len(writeSetPolicies) == 0 &&
			len(readSetValues) == 0 &&
			len(writeSetValues) == 0 &&
			len(readSetGroups) == 0 &&
			len(writeSetGroups) == 0 {
			return &cb.ConfigGroup{
					Version: original.Version,
				}, &cb.ConfigGroup{
					Version: original.Version,
				}, false
		}

		return &cb.ConfigGroup{
				Version:  original.Version,
				Policies: readSetPolicies,
				Values:   readSetValues,
				Groups:   readSetGroups,
			}, &cb.ConfigGroup{
				Version:  original.Version,
				Policies: writeSetPolicies,
				Values:   writeSetValues,
				Groups:   writeSetGroups,
			}, true
	}

	for k, samePolicy := range sameSetPolicies {
		readSetPolicies[k] = samePolicy
		writeSetPolicies[k] = samePolicy
	}

	for k, sameValue := range sameSetValues {
		readSetValues[k] = sameValue
		writeSetValues[k] = sameValue
	}

	for k, sameGroup := range sameSetGroups {
		readSetGroups[k] = sameGroup
		writeSetGroups[k] = sameGroup
	}

	return &cb.ConfigGroup{
			Version:  original.Version,
			Policies: readSetPolicies,
			Values:   readSetValues,
			Groups:   readSetGroups,
		}, &cb.ConfigGroup{
			Version:   original.Version + 1,
			Policies:  writeSetPolicies,
			Values:    writeSetValues,
			Groups:    writeSetGroups,
			ModPolicy: updated.ModPolicy,
		}, true
}

func Compute(original, updated *cb.Config) (*cb.ConfigUpdate, error) {
	if original.ChannelGroup == nil {
		return nil, fmt.Errorf("no channel group included for original config")
	}

	if updated.ChannelGroup == nil {
		return nil, fmt.Errorf("no channel group included for updated config")
	}

	readSet, writeSet, groupUpdated := computeGroupUpdate(original.ChannelGroup, updated.ChannelGroup)
	if !groupUpdated {
		return nil, fmt.Errorf("no differences detected between original and updated config")
	}
	return &cb.ConfigUpdate{
		ReadSet:  readSet,
		WriteSet: writeSet,
	}, nil
}

//func JSONtoConfig(r io.Reader) error {
func JSONtoConfig(filename string) (map[string]interface{}, error) {

	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("ReadFile: ", err.Error())
		return nil, err
	}
	configJSON := make(map[string]interface{})
	if err := json.Unmarshal(bytes, &configJSON); err != nil {
		fmt.Println("Unmarshal: ", err.Error())
		return nil, err
	}
	//fmt.Printf("read JSON config as %s \n",configJSON)
	return configJSON, err
}

func ConfigToJSON(jsonconfig map[string]interface{}) {
	//b, err := json.Marshal(jsonconfig)
	b, err := json.MarshalIndent(jsonconfig, "", "      ")
	//_, err := json.MarshalIndent(jsonconfig, "", "      ")
	if err != nil {
		fmt.Println("config to JSON failed:", err)
		return
	}
	fmt.Println(os.Args[1])
	fmt.Println("convert map JSON file is: ", string(b))
}

func jsonToMap(marshaled []byte) (map[string]interface{}, error) {
	tree := make(map[string]interface{})
	d := json.NewDecoder(bytes.NewReader(marshaled))
	d.UseNumber()
	err := d.Decode(&tree)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling intermediate JSON: %s", err)
	}
	return tree, nil
}

// EncodeProtoOrig to encode config group to Proto []byte
func EncodeProtoOrig(msgName string, input map[string]interface{}) ([]byte, error) {
	msgType := proto.MessageType(msgName)
	if msgType == nil {
		return nil, errors.Errorf("message of type %s unknown", msgType)
	}
	msg := reflect.New(msgType.Elem()).Interface().(proto.Message)

	// err := protolator.DeepUnmarshalJSON(input, msg)
	// if err != nil {
	// 	return nil,errors.Wrapf(err, "error decoding input")
	// }
	//protolator.RecursivelyPopulateMessageFromConfig(input msg)
	err := protolator.DeepUnmarshalMap(input, msg)
	if err != nil {
		return nil, errors.Wrapf(err, "error DeepUnmarshalMap input")
	}

	out, err := proto.Marshal(msg)
	if err != nil {
		return nil, errors.Wrapf(err, "error marshaling")
	}

	// _, err = output.Write(out)
	// if err != nil {
	// 	return errors.Wrapf(err, "error writing output")
	// }
	fmt.Printf("EncodeProtoOrig success")
	return out, err
}

func EncodeAndReplaceNull(mapJson map[string]interface{}) *bytes.Buffer {
	var updatedBuffer bytes.Buffer
	encoderUpdated := json.NewEncoder(&updatedBuffer)
	encoderUpdated.SetIndent("", "\t")
	encoderUpdated.Encode(mapJson)

	r := regexp.MustCompile("\"signing_identity\":[ ]{0,}null,\n")
	out := r.ReplaceAllString(string(updatedBuffer.Bytes()), "")
	r = regexp.MustCompile("\"fabricNodeOus\":[ ]{0,}null,\n")
	out = r.ReplaceAllString(out, "")
	r = regexp.MustCompile("\"value\":[ ]{0,}null,\n")
	out = r.ReplaceAllString(out, "")
	r = regexp.MustCompile("\"policy\":[ ]{0,}null,\n")
	out = r.ReplaceAllString(out, "")
	r = regexp.MustCompile("\"crypto_config\":[ ]{0,}null,\n")
	out = r.ReplaceAllString(out, "")

	return bytes.NewBuffer([]byte(out))
}
