package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"

	"github.com/gorilla/sessions"
	"github.com/spf13/viper"
)

var store *sessions.FilesystemStore

type claims struct {
	Subject           string   `json:"sub"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Verified          bool     `json:"email_verified"`
	Roles             []string `json:"roles"`
}

func initSessionStore() {
	sessionKey, _ := base64.StdEncoding.DecodeString(viper.GetString("session_store_key"))
	store = sessions.NewFilesystemStore("", sessionKey)
	store.MaxLength(0x10000)
	store.MaxAge(3600)
	gob.Register(claims{})
	gob.Register(map[string]interface{}{})
}

func dumpSession(sv map[interface{}]interface{}) []byte {
	b := &bytes.Buffer{}
	for k := range sv {
		if kk, ok := k.(string); ok {
			switch v := sv[k].(type) {
			case string:
				fmt.Fprintf(b, "%s: %s\n", kk, v)
			case map[string]interface{}:
				fmt.Fprintf(b, "%s:\n", k)
				for pk := range v {
					fmt.Fprintf(b, "  %s: %s\n", pk, v[pk])
				}
			case claims:
				j, _ := json.MarshalIndent(v, "", "\t")
				fmt.Fprintf(b, "claims: %s\n", string(j))
			}
		}
	}
	return b.Bytes()
}
