package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/docker/libtrust"
)

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
