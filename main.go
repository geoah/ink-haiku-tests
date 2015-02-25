package main

import (
	"fmt"
	"log"
)

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

	instanceJSON, _ := instance.ToJSON()
	fmt.Println(string(instanceJSON))
	// instance.Payload.ID = "1"
	if instance.Verify() == true {
		log.Println("VALID")
	} else {
		log.Fatal("ERROR")
	}

}
