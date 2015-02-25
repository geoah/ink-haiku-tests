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

func (s *Identity) Init() error {
	// Generate RSA 2048 Key
	// fmt.Printf("Generating RSA 2048-bit Key")
	rsaKey, err := libtrust.GenerateRSA2048PrivateKey()
	if err != nil {
		return err
	}

	// Create JWK for Private Key
	privateJWKJSON, err := json.MarshalIndent(rsaKey, "", "    ")
	if err != nil {
		return err
	}
	err = json.Unmarshal(privateJWKJSON, &s.PrivateJwk)
	// fmt.Printf("JWK Private Key (identity._jwk): \n%s\n\n", string(privateJWKJSON))
	if err != nil {
		return err
	}

	// Create JWK for Public Key
	publicJWKJSON, err := json.MarshalIndent(rsaKey.PublicKey(), "", "    ")
	if err != nil {
		return err
	}
	// fmt.Printf("JWK Public Key (identity.jwk): \n%s\n\n", string(publicJWKJSON))
	err = json.Unmarshal(publicJWKJSON, &s.PublicJwk)
	if err != nil {
		return err
	}

	// Create Thumbprint for Private Key
	thumbprint, err := makeThumbprint(rsaKey)
	if err != nil {
		return err
	}
	// fmt.Printf("Identity Thumbprint Hex String (identity.id): \n%s\n\n", thumbprint)
	s.Id = thumbprint
	if err != nil {
		return err
	}

	return nil
}

func (s *Identity) GetPrivateKeyJson() ([]byte, error) {
	return json.MarshalIndent(s.PrivateJwk, "", "")
}

func (s *Identity) GetPublicKeyJson() ([]byte, error) {
	return json.MarshalIndent(s.PublicJwk, "", "")
}

func (s *Identity) GetPrivateKey() (libtrust.PrivateKey, error) {
	jwk, err := s.GetPrivateKeyJson()
	if err != nil {
		return nil, err
	}
	return libtrust.UnmarshalPrivateKeyJWK(jwk)
}

func (s *Identity) GetPublicKey() (libtrust.PublicKey, error) {
	jwk, err := s.GetPublicKeyJson()
	if err != nil {
		return nil, err
	}
	return libtrust.UnmarshalPublicKeyJWK(jwk)
}

// Create a thumbprint accoring to draft 31 of JWK Thumbprint
// https://datatracker.ietf.org/doc/draft-jones-jose-jwk-thumbprint/
func makeThumbprint(rsaKey libtrust.PrivateKey) (string, error) {
	// TODO This is a very ungly hack.
	// libtrust.PrivateKey.toMap() is not public
	// libtrust.util.joseBase64UrlEncode() etc are not public.
	// So didn't really find a way to get them out of the object! :/

	// Convert the rsaKey to JSON
	privateJWKJSON, err := json.MarshalIndent(rsaKey, "", "")
	if err != nil {
		return "", err
	}
	// And then back to a map
	var data interface{}
	err = json.Unmarshal(privateJWKJSON, &data)
	if err != nil {
		return "", err
	}
	privateJWKMap := data.(map[string]interface{})
	// Now we just create a new map and push only what we need.
	jwkSimple := make(map[string]interface{})
	jwkSimple["e"] = privateJWKMap["e"]
	jwkSimple["kty"] = privateJWKMap["kty"]
	jwkSimple["n"] = privateJWKMap["n"]
	// Marshal it into a json as required by JKT
	jwkJsonString, err := json.Marshal(jwkSimple)
	if err != nil {
		return "", err
	}
	// Finally SHA256 it, encode in HEX and return it
	hash := sha256.New()
	hash.Write(jwkJsonString)
	thumbprint := hash.Sum(nil)
	jwtHex := hex.EncodeToString(thumbprint)

	return jwtHex, nil
}
