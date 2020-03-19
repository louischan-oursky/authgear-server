// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package oauth

import (
	"github.com/skygeario/skygear-server/pkg/auth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/oauth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/handler"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/oidc"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/urlprefix"
	"github.com/skygeario/skygear-server/pkg/core/time"
	"net/http"
)

// Injectors from wire.go:

func newAuthorizeHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	provider := urlprefix.NewProvider(r)
	endpointsProvider := &auth.EndpointsProvider{
		PrefixProvider: provider,
	}
	scopesValidator := _wireScopesValidatorValue
	tokenGenerator := _wireTokenGeneratorValue
	timeProvider := time.NewProvider()
	authorizationHandler := handler.ProvideAuthorizationHandler(context, tenantConfiguration, endpointsProvider, endpointsProvider, scopesValidator, tokenGenerator, timeProvider)
	httpHandler := provideAuthorizeHandler(authorizationHandler)
	return httpHandler
}

var (
	_wireScopesValidatorValue = handler.ScopesValidator(oidc.ValidateScopes)
	_wireTokenGeneratorValue  = handler.TokenGenerator(handler.GenerateToken)
)

func newMetadataHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	provider := urlprefix.NewProvider(r)
	endpointsProvider := &auth.EndpointsProvider{
		PrefixProvider: provider,
	}
	metadataProvider := &oauth.MetadataProvider{
		URLPrefix:            provider,
		AuthorizeEndpoint:    endpointsProvider,
		TokenEndpoint:        endpointsProvider,
		AuthenticateEndpoint: endpointsProvider,
	}
	oidcMetadataProvider := &oidc.MetadataProvider{}
	httpHandler := provideMetadataHandler(metadataProvider, oidcMetadataProvider)
	return httpHandler
}

// wire.go:

func provideAuthorizeHandler(ah oauthAuthorizeHandler) http.Handler {
	h := &AuthorizeHandler{
		authzHandler: ah,
	}
	return h
}

func provideMetadataHandler(oauth2 *oauth.MetadataProvider, oidc2 *oidc.MetadataProvider) http.Handler {
	h := &MetadataHandler{
		metaProviders: []oauthMetadataProvider{oauth2, oidc2},
	}
	return h
}
