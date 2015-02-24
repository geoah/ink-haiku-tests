package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/docker/libtrust"
)

func joseBase64UrlEncode(b []byte) []byte {
	return []byte(strings.TrimRight(base64.URLEncoding.EncodeToString(b), "="))
}

type Identity struct {
	Id         string                 `json:"id"`
	PrivateJwk map[string]interface{} `json:"_jwk"`
	PublicJwk  map[string]interface{} `json:"jwk"`
}

func (s *Identity) Init() {
	// Generate RSA 2048 Key
	// fmt.Printf("Generating RSA 2048-bit Key")
	rsaKey, _ := libtrust.GenerateRSA2048PrivateKey()

	// Create JWK for Private Key
	privateJWKJSON, _ := json.MarshalIndent(rsaKey, "", "    ")
	json.Unmarshal(privateJWKJSON, &s.PrivateJwk)
	// fmt.Printf("JWK Private Key (identity._jwk): \n%s\n\n", string(privateJWKJSON))

	// Create JWK for Public Key
	publicJWKJSON, _ := json.MarshalIndent(rsaKey.PublicKey(), "", "    ")
	// fmt.Printf("JWK Public Key (identity.jwk): \n%s\n\n", string(publicJWKJSON))
	json.Unmarshal(publicJWKJSON, &s.PublicJwk)

	// Create Thumbprint for Private Key
	thumbprint := makeThumbprint(rsaKey)
	// fmt.Printf("Identity Thumbprint Hex String (identity.id): \n%s\n\n", thumbprint)
	s.Id = thumbprint
}

func (s *Identity) GetPrivateKeyJson() []byte {
	privateJWKJSON, _ := json.MarshalIndent(s.PrivateJwk, "", "")
	return privateJWKJSON
}

func (s *Identity) GetPublicKeyJson() []byte {
	publicJWKJSON, _ := json.MarshalIndent(s.PublicJwk, "", "")
	return publicJWKJSON
}

func (s *Identity) GetPrivateKey() libtrust.PrivateKey {
	privateKey, _ := libtrust.UnmarshalPrivateKeyJWK(s.GetPrivateKeyJson())
	return privateKey
}

func (s *Identity) GetPublicKey() libtrust.PublicKey {
	publicKey, _ := libtrust.UnmarshalPublicKeyJWK(s.GetPublicKeyJson())
	return publicKey
}

// Create a thumbprint accoring to draft 31 of JWK Thumbprint
// https://datatracker.ietf.org/doc/draft-jones-jose-jwk-thumbprint/
func makeThumbprint(rsaKey libtrust.PrivateKey) string {
	// TODO This is a very ungly hack.
	// libtrust.PrivateKey.toMap() is not public
	// libtrust.util.joseBase64UrlEncode() etc are not public.
	// So didn't really find a way to get them out of the object! :/

	// Convert the rsaKey to JSON
	privateJWKJSON, _ := json.MarshalIndent(rsaKey, "", "")
	// And then back to a map
	var data interface{}
	json.Unmarshal(privateJWKJSON, &data)
	privateJWKMap := data.(map[string]interface{})
	// Now we just create a new map and push only what we need.
	jwkSimple := make(map[string]interface{})
	jwkSimple["e"] = privateJWKMap["e"]
	jwkSimple["kty"] = privateJWKMap["kty"]
	jwkSimple["n"] = privateJWKMap["n"]
	// Marshal it into a json as required by JKT
	jwkJsonString, _ := json.Marshal(jwkSimple)
	// Finally SHA256 it, encode in HEX and return it
	hash := sha256.New()
	hash.Write(jwkJsonString)
	thumbprint := hash.Sum(nil)
	jwtHex := hex.EncodeToString(thumbprint)

	return jwtHex
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

func (s *Instance) SetPayloadFromJson(jsonPayload []byte) {
	json.Unmarshal(jsonPayload, &s.Payload)
}

func (s *Instance) Sign() {
	payload, err := s.Payload.ToJSON()
	if err != nil {
		log.Println("Could not encode payload")
		log.Fatal(err)
	}
	// fmt.Println(string(payload))
	js, err := libtrust.NewJSONSignature(payload)
	if err != nil {
		log.Println("Could not create jsign")
		log.Fatal(err)
	}
	// fmt.Println(js)
	err = js.Sign(s.Owner.GetPrivateKey())
	if err != nil {
		log.Println("Could not sign payload")
		log.Fatal(err)
	}
	jsJSON, err := js.JWS()
	// fmt.Println(string(jsJSON))
	tempJSONSignature := JSONSignature{}
	json.Unmarshal(jsJSON, &tempJSONSignature)
	s.Payload.Signatures = tempJSONSignature.Signatures

	// prettySign, _ := js.PrettySignature("signatures")
	// fmt.Println(string(prettySign))

	// js2, err := libtrust.ParsePrettySignature(prettySign, "signatures")
	// if err != nil {
	// 	log.Println("Could not re-create jws")
	// 	log.Fatal(err)
	// }
	// ks, err := js2.Verify()
	// if err != nil {
	// 	log.Println("Could not verify")
	// 	log.Fatal(err)
	// } else {
	// 	log.Println("VALID")
	// 	log.Println(ks)
	// }
	// fmt.Println(string(s.ToJSON())
}

func (s *Instance) Verify() bool {
	jws, _ := s.GetProperJWS()
	_, err := jws.Verify()
	if err != nil {
		fmt.Println(err)
		return false
	} else {
		return true
	}
}

// func (s *Instance) Verify() {
// 	js2, err := libtrust.ParseJWS(jsJSON)
// 	keys, err := js2.Verify()
// 	if err != nil {
// 		fmt.Println("COULD NOT VERIFY SIGNATURE")
// 	} else {
// 		fmt.Println(keys)
// 		fmt.Println("js is valid")
// 	}
// }

type PayloadLibtrust struct {
	Payload    string      `json:"payload"`
	Signatures interface{} `json:"signatures,omitempty"`
}

func main() {
	identity := Identity{}
	identity.Init()
	fmt.Println("Identity.ID " + identity.Id)

	jsonPayload := `{
      "id": "6bf77fce-1275-4ac1-9e0b-81c7580bb2ee",
      "owner": "dd92ad1e-a7f6-46e7-8357-eb2a056ebc9b",
      "schema": "dummy.schema.ink",
      "version": {
          "id": "e58185f4-4e78-4f4d-a224-9666f8940f43",
          "app": {
              "name": "random-app",
              "version": "1.0.0",
              "url": "https://random-app"
          },
          "message": "commit message",
          "created": 123456789,
          "updated": 123456789,
          "removed": 123456789,
          "received": 123456789
      },
      "permissions": {
          "public": false,
          "identities": {
              "de999afe-f9fe-48f2-9828-c078e146f47d": {
                  "archive": true,
                  "modify": false,
                  "remove": false
              },
              "b24bee83-c797-4fb3-a79a-df1e97104fcd": {
                  "archive": true,
                  "modify": false,
                  "remove": false
              }
          }
      }
  }`
	instance := Instance{}
	instance.Owner = identity
	instance.SetPayloadFromJson([]byte(jsonPayload))
	fmt.Println("Instance.ID " + instance.Payload.ID)

	instance.Sign()

	instanceJSON, _ := instance.Payload.ToJSON()
	fmt.Println(string(instanceJSON))

	if instance.Verify() == true {
		log.Println("VALID")
	} else {
		log.Fatal("ERROR")
	}

}
