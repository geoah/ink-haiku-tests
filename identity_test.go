package main

import "testing"

func TestIdentityInit(t *testing.T) {
	identity := Identity{}
	identity.Init()

	if len(identity.Id) != 64 {
		t.Errorf("Error creating identity thumbprint (identity.id), character length is %d instead of 64.", len(identity.Id))
	}

	jwk, err := identity.GetPrivateKey()
	if jwk == nil || err != nil {
		t.Fatalf("Could not get private key. ERROR: %s", err)
	}
	if jwk.KeyType() != "RSA" {
		t.Fatalf("key type must be %q, instead got %q", "RSA", jwk.KeyType())
	}
}
