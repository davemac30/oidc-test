package main

import (
	"context"
	"fmt"
	"log"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

type authenticator struct {
	provider *oidc.Provider
	config   oauth2.Config
	ctx      context.Context
}

var auth *authenticator

func newAuthenticator() (*authenticator, error) {
	ctx := context.Background()

	providerURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", viper.GetString("aad_tenant_id"))
	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		log.Printf("failed to get provider: %v", err)
		return nil, err
	}

	conf := oauth2.Config{
		ClientID:     viper.GetString("aad_client_id"),
		ClientSecret: viper.GetString("aad_client_secret"),
		RedirectURL:  viper.GetString("aad_callback_url"),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}

	return &authenticator{
		provider: provider,
		config:   conf,
		ctx:      ctx,
	}, nil
}
