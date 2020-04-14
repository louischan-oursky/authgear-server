// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package sso

import (
	"github.com/gorilla/mux"
	"github.com/skygeario/skygear-server/pkg/auth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/audit"
	auth2 "github.com/skygeario/skygear-server/pkg/auth/dependency/auth"
	redis2 "github.com/skygeario/skygear-server/pkg/auth/dependency/auth/redis"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/authn"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/hook"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/loginid"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/mfa"
	pq3 "github.com/skygeario/skygear-server/pkg/auth/dependency/mfa/pq"
	oauth2 "github.com/skygeario/skygear-server/pkg/auth/dependency/oauth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/handler"
	pq4 "github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/pq"
	redis3 "github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/redis"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/oidc"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/passwordhistory/pq"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/principal"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/principal/oauth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/principal/password"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/session"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/session/redis"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/sso"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/urlprefix"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/userprofile"
	"github.com/skygeario/skygear-server/pkg/core/async"
	"github.com/skygeario/skygear-server/pkg/core/auth/authinfo"
	pq2 "github.com/skygeario/skygear-server/pkg/core/auth/authinfo/pq"
	"github.com/skygeario/skygear-server/pkg/core/config"
	"github.com/skygeario/skygear-server/pkg/core/db"
	handler2 "github.com/skygeario/skygear-server/pkg/core/handler"
	"github.com/skygeario/skygear-server/pkg/core/logging"
	"github.com/skygeario/skygear-server/pkg/core/mail"
	"github.com/skygeario/skygear-server/pkg/core/sms"
	"github.com/skygeario/skygear-server/pkg/core/time"
	"github.com/skygeario/skygear-server/pkg/core/validation"
	"net/http"
)

// Injectors from wire.go:

func newAuthHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	provider := urlprefix.NewProvider(r)
	authHandlerHTMLProvider := sso.ProvideAuthHandlerHTMLProvider(provider)
	ssoProvider := sso.ProvideSSOProvider(context, tenantConfiguration)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	timeProvider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(timeProvider, sqlBuilder, sqlExecutor)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, timeProvider, store, factory, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideOAuthProvider(sqlBuilder, sqlExecutor)
	v := auth.ProvidePrincipalProviders(oauthProvider, passwordProvider)
	identityProvider := principal.ProvideIdentityProvider(sqlBuilder, sqlExecutor, v)
	authenticateProcess := authn.ProvideAuthenticateProcess(factory, timeProvider, passwordProvider, oauthProvider, identityProvider)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	loginIDChecker := loginid.ProvideLoginIDChecker(tenantConfiguration, reservedNameChecker)
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(timeProvider, sqlBuilder, sqlExecutor)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, timeProvider, authinfoStore, userprofileStore, passwordProvider, factory)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	signupProcess := authn.ProvideSignupProcess(passwordChecker, loginIDChecker, identityProvider, passwordProvider, oauthProvider, timeProvider, authinfoStore, userprofileStore, hookProvider, tenantConfiguration, provider, queue)
	oAuthCoordinator := &authn.OAuthCoordinator{
		Authn:  authenticateProcess,
		Signup: signupProcess,
	}
	mfaStore := pq3.ProvideStore(tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider)
	client := sms.ProvideSMSClient(context, tenantConfiguration)
	sender := mail.ProvideMailSender(context, tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	mfaSender := mfa.ProvideMFASender(tenantConfiguration, client, sender, engine)
	mfaProvider := mfa.ProvideMFAProvider(mfaStore, tenantConfiguration, timeProvider, mfaSender)
	sessionStore := redis.ProvideStore(context, tenantConfiguration, timeProvider, factory)
	eventStore := redis2.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, accessEventProvider, tenantConfiguration)
	authorizationStore := &pq4.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis3.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider)
	authAccessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, provider, authinfoStore, userprofileStore, identityProvider, timeProvider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, authAccessEventProvider, sessionProvider, idTokenIssuer, tokenGenerator, timeProvider)
	authnSessionProvider := authn.ProvideSessionProvider(mfaProvider, sessionProvider, tenantConfiguration, timeProvider, authinfoStore, userprofileStore, identityProvider, hookProvider, tokenHandler)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	mfaInsecureCookieConfig := auth.ProvideMFAInsecureCookieConfig(m)
	bearerTokenCookieConfiguration := mfa.ProvideBearerTokenCookieConfiguration(r, mfaInsecureCookieConfig, tenantConfiguration)
	providerFactory := &authn.ProviderFactory{
		OAuth:                   oAuthCoordinator,
		Authn:                   authenticateProcess,
		Signup:                  signupProcess,
		AuthnSession:            authnSessionProvider,
		Session:                 sessionProvider,
		SessionCookieConfig:     cookieConfiguration,
		BearerTokenCookieConfig: bearerTokenCookieConfiguration,
	}
	authnProvider := authn.ProvideAuthAPIProvider(providerFactory)
	loginIDNormalizerFactory := loginid.ProvideLoginIDNormalizerFactory(tenantConfiguration)
	redirectURLFunc := ProvideRedirectURIForAPIFunc()
	oAuthProviderFactory := sso.ProvideOAuthProviderFactory(tenantConfiguration, provider, timeProvider, loginIDNormalizerFactory, redirectURLFunc)
	oAuthProvider := provideOAuthProviderFromRequestVars(r, oAuthProviderFactory)
	httpHandler := provideAuthHandler(txContext, tenantConfiguration, authHandlerHTMLProvider, ssoProvider, authnProvider, oAuthProvider)
	return httpHandler
}

var (
	_wireTokenGeneratorValue = handler.TokenGenerator(oauth2.GenerateToken)
)

func newAuthResultHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	requireAuthz := handler2.NewRequireAuthzFactory(factory)
	provider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, provider, store, factory, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideOAuthProvider(sqlBuilder, sqlExecutor)
	v := auth.ProvidePrincipalProviders(oauthProvider, passwordProvider)
	identityProvider := principal.ProvideIdentityProvider(sqlBuilder, sqlExecutor, v)
	authenticateProcess := authn.ProvideAuthenticateProcess(factory, provider, passwordProvider, oauthProvider, identityProvider)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	loginIDChecker := loginid.ProvideLoginIDChecker(tenantConfiguration, reservedNameChecker)
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(provider, sqlBuilder, sqlExecutor)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, provider, authinfoStore, userprofileStore, passwordProvider, factory)
	urlprefixProvider := urlprefix.NewProvider(r)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	signupProcess := authn.ProvideSignupProcess(passwordChecker, loginIDChecker, identityProvider, passwordProvider, oauthProvider, provider, authinfoStore, userprofileStore, hookProvider, tenantConfiguration, urlprefixProvider, queue)
	oAuthCoordinator := &authn.OAuthCoordinator{
		Authn:  authenticateProcess,
		Signup: signupProcess,
	}
	mfaStore := pq3.ProvideStore(tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	client := sms.ProvideSMSClient(context, tenantConfiguration)
	sender := mail.ProvideMailSender(context, tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	mfaSender := mfa.ProvideMFASender(tenantConfiguration, client, sender, engine)
	mfaProvider := mfa.ProvideMFAProvider(mfaStore, tenantConfiguration, provider, mfaSender)
	sessionStore := redis.ProvideStore(context, tenantConfiguration, provider, factory)
	eventStore := redis2.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, accessEventProvider, tenantConfiguration)
	authorizationStore := &pq4.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis3.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	authAccessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, urlprefixProvider, authinfoStore, userprofileStore, identityProvider, provider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, authAccessEventProvider, sessionProvider, idTokenIssuer, tokenGenerator, provider)
	authnSessionProvider := authn.ProvideSessionProvider(mfaProvider, sessionProvider, tenantConfiguration, provider, authinfoStore, userprofileStore, identityProvider, hookProvider, tokenHandler)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	mfaInsecureCookieConfig := auth.ProvideMFAInsecureCookieConfig(m)
	bearerTokenCookieConfiguration := mfa.ProvideBearerTokenCookieConfiguration(r, mfaInsecureCookieConfig, tenantConfiguration)
	providerFactory := &authn.ProviderFactory{
		OAuth:                   oAuthCoordinator,
		Authn:                   authenticateProcess,
		Signup:                  signupProcess,
		AuthnSession:            authnSessionProvider,
		Session:                 sessionProvider,
		SessionCookieConfig:     cookieConfiguration,
		BearerTokenCookieConfig: bearerTokenCookieConfiguration,
	}
	authnProvider := authn.ProvideAuthAPIProvider(providerFactory)
	validator := auth.ProvideValidator(m)
	ssoProvider := sso.ProvideSSOProvider(context, tenantConfiguration)
	httpHandler := provideAuthResultHandler(txContext, requireAuthz, authnProvider, validator, ssoProvider)
	return httpHandler
}

func newLinkHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	requireAuthz := handler2.NewRequireAuthzFactory(factory)
	validator := auth.ProvideValidator(m)
	provider := sso.ProvideSSOProvider(context, tenantConfiguration)
	timeProvider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(timeProvider, sqlBuilder, sqlExecutor)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, timeProvider, store, factory, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideOAuthProvider(sqlBuilder, sqlExecutor)
	v := auth.ProvidePrincipalProviders(oauthProvider, passwordProvider)
	identityProvider := principal.ProvideIdentityProvider(sqlBuilder, sqlExecutor, v)
	authenticateProcess := authn.ProvideAuthenticateProcess(factory, timeProvider, passwordProvider, oauthProvider, identityProvider)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	loginIDChecker := loginid.ProvideLoginIDChecker(tenantConfiguration, reservedNameChecker)
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(timeProvider, sqlBuilder, sqlExecutor)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, timeProvider, authinfoStore, userprofileStore, passwordProvider, factory)
	urlprefixProvider := urlprefix.NewProvider(r)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	signupProcess := authn.ProvideSignupProcess(passwordChecker, loginIDChecker, identityProvider, passwordProvider, oauthProvider, timeProvider, authinfoStore, userprofileStore, hookProvider, tenantConfiguration, urlprefixProvider, queue)
	oAuthCoordinator := &authn.OAuthCoordinator{
		Authn:  authenticateProcess,
		Signup: signupProcess,
	}
	mfaStore := pq3.ProvideStore(tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider)
	client := sms.ProvideSMSClient(context, tenantConfiguration)
	sender := mail.ProvideMailSender(context, tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	mfaSender := mfa.ProvideMFASender(tenantConfiguration, client, sender, engine)
	mfaProvider := mfa.ProvideMFAProvider(mfaStore, tenantConfiguration, timeProvider, mfaSender)
	sessionStore := redis.ProvideStore(context, tenantConfiguration, timeProvider, factory)
	eventStore := redis2.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, accessEventProvider, tenantConfiguration)
	authorizationStore := &pq4.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis3.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider)
	authAccessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, urlprefixProvider, authinfoStore, userprofileStore, identityProvider, timeProvider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, authAccessEventProvider, sessionProvider, idTokenIssuer, tokenGenerator, timeProvider)
	authnSessionProvider := authn.ProvideSessionProvider(mfaProvider, sessionProvider, tenantConfiguration, timeProvider, authinfoStore, userprofileStore, identityProvider, hookProvider, tokenHandler)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	mfaInsecureCookieConfig := auth.ProvideMFAInsecureCookieConfig(m)
	bearerTokenCookieConfiguration := mfa.ProvideBearerTokenCookieConfiguration(r, mfaInsecureCookieConfig, tenantConfiguration)
	providerFactory := &authn.ProviderFactory{
		OAuth:                   oAuthCoordinator,
		Authn:                   authenticateProcess,
		Signup:                  signupProcess,
		AuthnSession:            authnSessionProvider,
		Session:                 sessionProvider,
		SessionCookieConfig:     cookieConfiguration,
		BearerTokenCookieConfig: bearerTokenCookieConfiguration,
	}
	authnProvider := authn.ProvideAuthAPIProvider(providerFactory)
	loginIDNormalizerFactory := loginid.ProvideLoginIDNormalizerFactory(tenantConfiguration)
	redirectURLFunc := ProvideRedirectURIForAPIFunc()
	oAuthProviderFactory := sso.ProvideOAuthProviderFactory(tenantConfiguration, urlprefixProvider, timeProvider, loginIDNormalizerFactory, redirectURLFunc)
	oAuthProvider := provideOAuthProviderFromRequestVars(r, oAuthProviderFactory)
	httpHandler := provideLinkHandler(txContext, requireAuthz, validator, provider, authnProvider, oAuthProvider)
	return httpHandler
}

func newLoginHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	requireAuthz := handler2.NewRequireAuthzFactory(factory)
	validator := auth.ProvideValidator(m)
	provider := sso.ProvideSSOProvider(context, tenantConfiguration)
	timeProvider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(timeProvider, sqlBuilder, sqlExecutor)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, timeProvider, store, factory, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideOAuthProvider(sqlBuilder, sqlExecutor)
	v := auth.ProvidePrincipalProviders(oauthProvider, passwordProvider)
	identityProvider := principal.ProvideIdentityProvider(sqlBuilder, sqlExecutor, v)
	authenticateProcess := authn.ProvideAuthenticateProcess(factory, timeProvider, passwordProvider, oauthProvider, identityProvider)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	loginIDChecker := loginid.ProvideLoginIDChecker(tenantConfiguration, reservedNameChecker)
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(timeProvider, sqlBuilder, sqlExecutor)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, timeProvider, authinfoStore, userprofileStore, passwordProvider, factory)
	urlprefixProvider := urlprefix.NewProvider(r)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	signupProcess := authn.ProvideSignupProcess(passwordChecker, loginIDChecker, identityProvider, passwordProvider, oauthProvider, timeProvider, authinfoStore, userprofileStore, hookProvider, tenantConfiguration, urlprefixProvider, queue)
	oAuthCoordinator := &authn.OAuthCoordinator{
		Authn:  authenticateProcess,
		Signup: signupProcess,
	}
	mfaStore := pq3.ProvideStore(tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider)
	client := sms.ProvideSMSClient(context, tenantConfiguration)
	sender := mail.ProvideMailSender(context, tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	mfaSender := mfa.ProvideMFASender(tenantConfiguration, client, sender, engine)
	mfaProvider := mfa.ProvideMFAProvider(mfaStore, tenantConfiguration, timeProvider, mfaSender)
	sessionStore := redis.ProvideStore(context, tenantConfiguration, timeProvider, factory)
	eventStore := redis2.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, accessEventProvider, tenantConfiguration)
	authorizationStore := &pq4.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis3.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider)
	authAccessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, urlprefixProvider, authinfoStore, userprofileStore, identityProvider, timeProvider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, authAccessEventProvider, sessionProvider, idTokenIssuer, tokenGenerator, timeProvider)
	authnSessionProvider := authn.ProvideSessionProvider(mfaProvider, sessionProvider, tenantConfiguration, timeProvider, authinfoStore, userprofileStore, identityProvider, hookProvider, tokenHandler)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	mfaInsecureCookieConfig := auth.ProvideMFAInsecureCookieConfig(m)
	bearerTokenCookieConfiguration := mfa.ProvideBearerTokenCookieConfiguration(r, mfaInsecureCookieConfig, tenantConfiguration)
	providerFactory := &authn.ProviderFactory{
		OAuth:                   oAuthCoordinator,
		Authn:                   authenticateProcess,
		Signup:                  signupProcess,
		AuthnSession:            authnSessionProvider,
		Session:                 sessionProvider,
		SessionCookieConfig:     cookieConfiguration,
		BearerTokenCookieConfig: bearerTokenCookieConfiguration,
	}
	authnProvider := authn.ProvideAuthAPIProvider(providerFactory)
	loginIDNormalizerFactory := loginid.ProvideLoginIDNormalizerFactory(tenantConfiguration)
	redirectURLFunc := ProvideRedirectURIForAPIFunc()
	oAuthProviderFactory := sso.ProvideOAuthProviderFactory(tenantConfiguration, urlprefixProvider, timeProvider, loginIDNormalizerFactory, redirectURLFunc)
	oAuthProvider := provideOAuthProviderFromRequestVars(r, oAuthProviderFactory)
	httpHandler := provideLoginHandler(txContext, requireAuthz, validator, provider, authnProvider, oAuthProvider)
	return httpHandler
}

func newAuthRedirectHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	provider := sso.ProvideSSOProvider(context, tenantConfiguration)
	urlprefixProvider := urlprefix.NewProvider(r)
	timeProvider := time.NewProvider()
	loginIDNormalizerFactory := loginid.ProvideLoginIDNormalizerFactory(tenantConfiguration)
	redirectURLFunc := ProvideRedirectURIForAPIFunc()
	oAuthProviderFactory := sso.ProvideOAuthProviderFactory(tenantConfiguration, urlprefixProvider, timeProvider, loginIDNormalizerFactory, redirectURLFunc)
	oAuthProvider := provideOAuthProviderFromRequestVars(r, oAuthProviderFactory)
	httpHandler := provideAuthRedirectHandler(provider, oAuthProvider)
	return httpHandler
}

func newLoginAuthURLHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	requireAuthz := handler2.NewRequireAuthzFactory(factory)
	validator := auth.ProvideValidator(m)
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	provider := time.NewProvider()
	store := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, provider, store, factory, tenantConfiguration, reservedNameChecker)
	ssoProvider := sso.ProvideSSOProvider(context, tenantConfiguration)
	urlprefixProvider := urlprefix.NewProvider(r)
	loginIDNormalizerFactory := loginid.ProvideLoginIDNormalizerFactory(tenantConfiguration)
	redirectURLFunc := ProvideRedirectURIForAPIFunc()
	oAuthProviderFactory := sso.ProvideOAuthProviderFactory(tenantConfiguration, urlprefixProvider, provider, loginIDNormalizerFactory, redirectURLFunc)
	oAuthProvider := provideOAuthProviderFromRequestVars(r, oAuthProviderFactory)
	ssoSsoAction := providerLoginSSOAction()
	httpHandler := provideAuthURLHandler(txContext, requireAuthz, validator, passwordProvider, ssoProvider, tenantConfiguration, oAuthProvider, ssoSsoAction)
	return httpHandler
}

func newLinkAuthURLHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	requireAuthz := handler2.NewRequireAuthzFactory(factory)
	validator := auth.ProvideValidator(m)
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	provider := time.NewProvider()
	store := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, provider, store, factory, tenantConfiguration, reservedNameChecker)
	ssoProvider := sso.ProvideSSOProvider(context, tenantConfiguration)
	urlprefixProvider := urlprefix.NewProvider(r)
	loginIDNormalizerFactory := loginid.ProvideLoginIDNormalizerFactory(tenantConfiguration)
	redirectURLFunc := ProvideRedirectURIForAPIFunc()
	oAuthProviderFactory := sso.ProvideOAuthProviderFactory(tenantConfiguration, urlprefixProvider, provider, loginIDNormalizerFactory, redirectURLFunc)
	oAuthProvider := provideOAuthProviderFromRequestVars(r, oAuthProviderFactory)
	ssoSsoAction := providerLinkSSOAction()
	httpHandler := provideAuthURLHandler(txContext, requireAuthz, validator, passwordProvider, ssoProvider, tenantConfiguration, oAuthProvider, ssoSsoAction)
	return httpHandler
}

func newUnlinkHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	provider := time.NewProvider()
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	userprofileStore := userprofile.ProvideStore(provider, sqlBuilder, sqlExecutor)
	oauthProvider := oauth.ProvideOAuthProvider(sqlBuilder, sqlExecutor)
	passwordhistoryStore := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, provider, passwordhistoryStore, factory, tenantConfiguration, reservedNameChecker)
	v := auth.ProvidePrincipalProviders(oauthProvider, passwordProvider)
	identityProvider := principal.ProvideIdentityProvider(sqlBuilder, sqlExecutor, v)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, provider, store, userprofileStore, passwordProvider, factory)
	sessionStore := redis.ProvideStore(context, tenantConfiguration, provider, factory)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	manager := session.ProvideSessionManager(sessionStore, provider, tenantConfiguration, cookieConfiguration)
	grantStore := redis3.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	sessionManager := &oauth2.SessionManager{
		Store: grantStore,
		Time:  provider,
	}
	authSessionManager := &auth2.SessionManager{
		AuthInfoStore:       store,
		UserProfileStore:    userprofileStore,
		IdentityProvider:    identityProvider,
		Hooks:               hookProvider,
		IDPSessions:         manager,
		AccessTokenSessions: sessionManager,
	}
	requireAuthz := handler2.NewRequireAuthzFactory(factory)
	urlprefixProvider := urlprefix.NewProvider(r)
	loginIDNormalizerFactory := loginid.ProvideLoginIDNormalizerFactory(tenantConfiguration)
	redirectURLFunc := ProvideRedirectURIForAPIFunc()
	oAuthProviderFactory := sso.ProvideOAuthProviderFactory(tenantConfiguration, urlprefixProvider, provider, loginIDNormalizerFactory, redirectURLFunc)
	httpHandler := providerUnlinkHandler(txContext, authSessionManager, requireAuthz, oauthProvider, store, userprofileStore, hookProvider, oAuthProviderFactory)
	return httpHandler
}

// wire.go:

func provideOAuthProviderFromRequestVars(r *http.Request, spf *sso.OAuthProviderFactory) sso.OAuthProvider {
	vars := mux.Vars(r)
	return spf.NewOAuthProvider(vars["provider"])
}

func ProvideRedirectURIForAPIFunc() sso.RedirectURLFunc {
	return RedirectURIForAPI
}

func provideAuthHandler(
	tx db.TxContext,
	cfg *config.TenantConfiguration,
	hp sso.AuthHandlerHTMLProvider,
	sp sso.Provider,
	ap AuthHandlerAuthnProvider,
	op sso.OAuthProvider,
) http.Handler {
	h := &AuthHandler{
		TxContext:               tx,
		TenantConfiguration:     cfg,
		AuthHandlerHTMLProvider: hp,
		SSOProvider:             sp,
		AuthnProvider:           ap,
		OAuthProvider:           op,
	}
	return h
}

func provideAuthResultHandler(
	tx db.TxContext,
	requireAuthz handler2.RequireAuthz,
	ap AuthResultAuthnProvider,
	v *validation.Validator,
	sp sso.Provider,
) http.Handler {
	h := &AuthResultHandler{
		TxContext:     tx,
		AuthnProvider: ap,
		Validator:     v,
		SSOProvider:   sp,
	}
	return requireAuthz(h, h)
}

func provideLinkHandler(
	tx db.TxContext,
	requireAuthz handler2.RequireAuthz,
	v *validation.Validator,
	sp sso.Provider,
	ap LinkAuthnProvider,
	op sso.OAuthProvider,
) http.Handler {
	h := &LinkHandler{
		TxContext:     tx,
		Validator:     v,
		SSOProvider:   sp,
		AuthnProvider: ap,
		OAuthProvider: op,
	}
	return requireAuthz(h, h)
}

func provideLoginHandler(
	tx db.TxContext,
	requireAuthz handler2.RequireAuthz,
	v *validation.Validator,
	sp sso.Provider,
	ap LoginAuthnProvider,
	op sso.OAuthProvider,
) http.Handler {
	h := &LoginHandler{
		TxContext:     tx,
		Validator:     v,
		SSOProvider:   sp,
		AuthnProvider: ap,
		OAuthProvider: op,
	}
	return requireAuthz(h, h)
}

func provideAuthRedirectHandler(
	sp sso.Provider,
	op sso.OAuthProvider,
) http.Handler {
	h := &AuthRedirectHandler{
		SSOProvider:   sp,
		OAuthProvider: op,
	}
	return h
}

func provideAuthURLHandler(
	tx db.TxContext,
	requireAuthz handler2.RequireAuthz,
	v *validation.Validator,
	pp password.Provider,
	sp sso.Provider,
	cfg *config.TenantConfiguration,
	op sso.OAuthProvider,
	action ssoAction,
) http.Handler {
	h := &AuthURLHandler{
		TxContext:                  tx,
		Validator:                  v,
		PasswordAuthProvider:       pp,
		SSOProvider:                sp,
		OAuthConflictConfiguration: cfg.AppConfig.AuthAPI.OnIdentityConflict.OAuth,
		OAuthProvider:              op,
		Action:                     action,
	}
	return requireAuthz(h, h)
}

func providerLoginSSOAction() ssoAction {
	return ssoActionLogin
}

func providerLinkSSOAction() ssoAction {
	return ssoActionLink
}

func providerUnlinkHandler(
	tx db.TxContext,
	sm unlinkSessionManager,
	requireAuthz handler2.RequireAuthz,
	oap oauth.Provider,
	ais authinfo.Store,
	ups userprofile.Store,
	hp hook.Provider,
	spf *sso.OAuthProviderFactory,
) http.Handler {
	h := &UnlinkHandler{
		TxContext:         tx,
		SessionManager:    sm,
		OAuthAuthProvider: oap,
		AuthInfoStore:     ais,
		UserProfileStore:  ups,
		HookProvider:      hp,
		ProviderFactory:   spf,
	}
	return requireAuthz(h, h)
}
