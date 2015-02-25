package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/docker/libtrust"
)

func joseBase64UrlEncode(b []byte) []byte {
	return []byte(strings.TrimRight(base64.URLEncoding.EncodeToString(b), "="))
}

type jsHeader struct {
	JWK       json.RawMessage `json:"jwk,omitempty"`
	Algorithm string          `json:"alg"`
	Chain     []string        `json:"x5c,omitempty"`
}

type jsSignature struct {
	Header    jsHeader `json:"header"`
	Signature string   `json:"signature"`
	Protected string   `json:"protected"`
}

// JSONSignature represents a signature of a json object.
type JSONSignature struct {
	Payload    string        `json:"payload"`
	Signatures []jsSignature `json:"signatures"`
	// indent       string
	// formatLength int
	// formatTail   []byte
}

type PayloadLibtrust struct {
	Payload    string      `json:"payload"`
	Signatures interface{} `json:"signatures,omitempty"`
}

type PayloadIdentities struct {
	Archive bool `json:"archive"`
	Modify  bool `json:"modify"`
	Remove  bool `json:"remove"`
}

type Payload struct {
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	Permissions struct {
		Identities map[string]PayloadIdentities `json:"identities"`
		Public     bool                         `json:"public"`
	} `json:"permissions"`
	Schema  string `json:"schema"`
	Version struct {
		App struct {
			Name    string `json:"name"`
			URL     string `json:"url"`
			Version string `json:"version"`
		} `json:"app"`
		Created  uint64 `json:"created"`
		ID       string `json:"id"`
		Message  string `json:"message"`
		Received uint64 `json:"received"`
		Removed  uint64 `json:"removed"`
		Updated  uint64 `json:"updated"`
	} `json:"version"`
	Signatures []jsSignature `json:"signatures,omitempty"`
}

func (s *Payload) ToJSON() ([]byte, error) {
	payloadStr, err := json.MarshalIndent(s, "", "     ")
	return payloadStr, err
}

type Instance struct {
	Owner   Identity `json:"owner"`
	Payload Payload  `json:"payload"`
}

func (s *Instance) ToJSON() ([]byte, error) {
	instanceStr, err := json.MarshalIndent(s, "", "     ")
	return instanceStr, err
}

func (s *Instance) GetProperJWS() (*libtrust.JSONSignature, error) {
	payloadJSON, _ := s.Payload.ToJSON()
	jws, err := libtrust.ParsePrettySignature(payloadJSON, "signatures")
	return jws, err
}

func (s *Instance) SetPayloadFromJson(jsonPayload []byte) { // TODO Return error
	json.Unmarshal(jsonPayload, &s.Payload)
}

func (s *Instance) Sign() { // TODO Return error
	payload, err := s.Payload.ToJSON()
	if err != nil {
		log.Println("Could not encode payload")
		log.Fatal(err)
	}
	js, err := libtrust.NewJSONSignature(payload)
	if err != nil {
		log.Println("Could not create jsign")
		log.Fatal(err)
	}
	err = js.Sign(s.Owner.GetPrivateKey())
	if err != nil {
		log.Println("Could not sign payload")
		log.Fatal(err)
	}
	jsJSON, err := js.JWS()
	tempJSONSignature := JSONSignature{}
	json.Unmarshal(jsJSON, &tempJSONSignature)
	s.Payload.Signatures = tempJSONSignature.Signatures
}

func (s *Instance) Verify() bool { // TODO Return error
	jws, _ := s.GetProperJWS()
	_, err := jws.Verify()
	if err != nil {
		fmt.Println(err)
		return false
	} else {
		return true
	}
}
