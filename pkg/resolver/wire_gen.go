// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package resolver

import (
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator/oob"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator/password"
	service2 "github.com/authgear/authgear-server/pkg/lib/authn/authenticator/service"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator/totp"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/anonymous"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/loginid"
	oauth2 "github.com/authgear/authgear-server/pkg/lib/authn/identity/oauth"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/service"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/lib/deps"
	"github.com/authgear/authgear-server/pkg/lib/facade"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
	"github.com/authgear/authgear-server/pkg/lib/infra/middleware"
	"github.com/authgear/authgear-server/pkg/lib/oauth"
	"github.com/authgear/authgear-server/pkg/lib/oauth/pq"
	"github.com/authgear/authgear-server/pkg/lib/oauth/redis"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/lib/session/access"
	"github.com/authgear/authgear-server/pkg/lib/session/idpsession"
	"github.com/authgear/authgear-server/pkg/resolver/handler"
	"github.com/authgear/authgear-server/pkg/util/clock"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/rand"
	"net/http"
)

// Injectors from wire.go:

func newSentryMiddleware(p *deps.RootProvider) httproute.Middleware {
	hub := p.SentryHub
	environmentConfig := p.EnvironmentConfig
	trustProxy := environmentConfig.TrustProxy
	sentryMiddleware := &middleware.SentryMiddleware{
		SentryHub:  hub,
		TrustProxy: trustProxy,
	}
	return sentryMiddleware
}

func newPanicEndMiddleware(p *deps.RootProvider) httproute.Middleware {
	panicEndMiddleware := &middleware.PanicEndMiddleware{}
	return panicEndMiddleware
}

func newPanicWriteEmptyResponseMiddleware(p *deps.RootProvider) httproute.Middleware {
	panicWriteEmptyResponseMiddleware := &middleware.PanicWriteEmptyResponseMiddleware{}
	return panicWriteEmptyResponseMiddleware
}

func newBodyLimitMiddleware(p *deps.RootProvider) httproute.Middleware {
	bodyLimitMiddleware := &middleware.BodyLimitMiddleware{}
	return bodyLimitMiddleware
}

func newPanicLogMiddleware(p *deps.RequestProvider) httproute.Middleware {
	appProvider := p.AppProvider
	factory := appProvider.LoggerFactory
	panicLogMiddlewareLogger := middleware.NewPanicLogMiddlewareLogger(factory)
	panicLogMiddleware := &middleware.PanicLogMiddleware{
		Logger: panicLogMiddlewareLogger,
	}
	return panicLogMiddleware
}

func newSessionMiddleware(p *deps.RequestProvider) httproute.Middleware {
	request := p.Request
	appProvider := p.AppProvider
	rootProvider := appProvider.RootProvider
	environmentConfig := rootProvider.EnvironmentConfig
	trustProxy := environmentConfig.TrustProxy
	cookieFactory := deps.NewCookieFactory(request, trustProxy)
	config := appProvider.Config
	appConfig := config.AppConfig
	httpConfig := appConfig.HTTP
	sessionConfig := appConfig.Session
	cookieDef := idpsession.NewSessionCookieDef(httpConfig, sessionConfig)
	handle := appProvider.Redis
	appID := appConfig.ID
	clock := _wireSystemClockValue
	factory := appProvider.LoggerFactory
	storeRedisLogger := idpsession.NewStoreRedisLogger(factory)
	storeRedis := &idpsession.StoreRedis{
		Redis:  handle,
		AppID:  appID,
		Clock:  clock,
		Logger: storeRedisLogger,
	}
	eventStoreRedis := &access.EventStoreRedis{
		Redis: handle,
		AppID: appID,
	}
	eventProvider := &access.EventProvider{
		Store: eventStoreRedis,
	}
	rand := _wireRandValue
	provider := &idpsession.Provider{
		Request:      request,
		Store:        storeRedis,
		AccessEvents: eventProvider,
		TrustProxy:   trustProxy,
		Config:       sessionConfig,
		Clock:        clock,
		Random:       rand,
	}
	resolver := &idpsession.Resolver{
		CookieFactory: cookieFactory,
		Cookie:        cookieDef,
		Provider:      provider,
		TrustProxy:    trustProxy,
		Clock:         clock,
	}
	secretConfig := config.SecretConfig
	databaseCredentials := deps.ProvideDatabaseCredentials(secretConfig)
	sqlBuilder := db.ProvideSQLBuilder(databaseCredentials, appID)
	context := deps.ProvideRequestContext(request)
	dbHandle := appProvider.Database
	sqlExecutor := db.SQLExecutor{
		Context:  context,
		Database: dbHandle,
	}
	authorizationStore := &pq.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	logger := redis.NewLogger(factory)
	grantStore := &redis.GrantStore{
		Redis:       handle,
		AppID:       appID,
		Logger:      logger,
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
		Clock:       clock,
	}
	oauthResolver := &oauth.Resolver{
		TrustProxy:     trustProxy,
		Authorizations: authorizationStore,
		AccessGrants:   grantStore,
		OfflineGrants:  grantStore,
		Sessions:       provider,
		Clock:          clock,
	}
	store := &user.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	authenticationConfig := appConfig.Authentication
	identityConfig := appConfig.Identity
	serviceStore := &service.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	loginidStore := &loginid.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	loginIDConfig := identityConfig.LoginID
	reservedNameChecker := rootProvider.ReservedNameChecker
	typeCheckerFactory := &loginid.TypeCheckerFactory{
		Config:              loginIDConfig,
		ReservedNameChecker: reservedNameChecker,
	}
	checker := &loginid.Checker{
		Config:             loginIDConfig,
		TypeCheckerFactory: typeCheckerFactory,
	}
	normalizerFactory := &loginid.NormalizerFactory{
		Config: loginIDConfig,
	}
	loginidProvider := &loginid.Provider{
		Store:             loginidStore,
		Config:            loginIDConfig,
		Checker:           checker,
		NormalizerFactory: normalizerFactory,
		Clock:             clock,
	}
	oauthStore := &oauth2.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	oauthProvider := &oauth2.Provider{
		Store: oauthStore,
		Clock: clock,
	}
	anonymousStore := &anonymous.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	anonymousProvider := &anonymous.Provider{
		Store: anonymousStore,
		Clock: clock,
	}
	store2 := &service2.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	passwordStore := &password.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	authenticatorConfig := appConfig.Authenticator
	authenticatorPasswordConfig := authenticatorConfig.Password
	passwordLogger := password.NewLogger(factory)
	historyStore := &password.HistoryStore{
		Clock:       clock,
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	passwordChecker := password.ProvideChecker(authenticatorPasswordConfig, historyStore)
	queue := appProvider.TaskQueue
	passwordProvider := &password.Provider{
		Store:           passwordStore,
		Config:          authenticatorPasswordConfig,
		Clock:           clock,
		Logger:          passwordLogger,
		PasswordHistory: historyStore,
		PasswordChecker: passwordChecker,
		TaskQueue:       queue,
	}
	totpStore := &totp.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	authenticatorTOTPConfig := authenticatorConfig.TOTP
	totpProvider := &totp.Provider{
		Store:  totpStore,
		Config: authenticatorTOTPConfig,
		Clock:  clock,
	}
	authenticatorOOBConfig := authenticatorConfig.OOB
	oobStore := &oob.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	oobProvider := &oob.Provider{
		Config: authenticatorOOBConfig,
		Store:  oobStore,
		Clock:  clock,
	}
	serviceService := &service2.Service{
		Store:    store2,
		Password: passwordProvider,
		TOTP:     totpProvider,
		OOBOTP:   oobProvider,
	}
	verificationLogger := verification.NewLogger(factory)
	verificationConfig := appConfig.Verification
	verificationStoreRedis := &verification.StoreRedis{
		Redis: handle,
		AppID: appID,
		Clock: clock,
	}
	storePQ := &verification.StorePQ{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	verificationService := &verification.Service{
		Logger:     verificationLogger,
		Config:     verificationConfig,
		Clock:      clock,
		CodeStore:  verificationStoreRedis,
		ClaimStore: storePQ,
	}
	service3 := &service.Service{
		Authentication: authenticationConfig,
		Identity:       identityConfig,
		Store:          serviceStore,
		LoginID:        loginidProvider,
		OAuth:          oauthProvider,
		Anonymous:      anonymousProvider,
		Authenticators: serviceService,
		Verification:   verificationService,
	}
	coordinator := &facade.Coordinator{
		Identities:     service3,
		Authenticators: serviceService,
	}
	identityFacade := facade.IdentityFacade{
		Coordinator: coordinator,
	}
	queries := &user.Queries{
		Store:        store,
		Identities:   identityFacade,
		Verification: verificationService,
	}
	sessionMiddleware := &session.Middleware{
		IDPSessionResolver:         resolver,
		AccessTokenSessionResolver: oauthResolver,
		AccessEvents:               eventProvider,
		Users:                      queries,
		Database:                   dbHandle,
	}
	return sessionMiddleware
}

var (
	_wireSystemClockValue = clock.NewSystemClock()
	_wireRandValue        = idpsession.Rand(rand.SecureRand)
)

func newSessionResolveHandler(p *deps.RequestProvider) http.Handler {
	appProvider := p.AppProvider
	config := appProvider.Config
	appConfig := config.AppConfig
	authenticationConfig := appConfig.Authentication
	identityConfig := appConfig.Identity
	secretConfig := config.SecretConfig
	databaseCredentials := deps.ProvideDatabaseCredentials(secretConfig)
	appID := appConfig.ID
	sqlBuilder := db.ProvideSQLBuilder(databaseCredentials, appID)
	request := p.Request
	context := deps.ProvideRequestContext(request)
	handle := appProvider.Database
	sqlExecutor := db.SQLExecutor{
		Context:  context,
		Database: handle,
	}
	store := &service.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	loginidStore := &loginid.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	loginIDConfig := identityConfig.LoginID
	rootProvider := appProvider.RootProvider
	reservedNameChecker := rootProvider.ReservedNameChecker
	typeCheckerFactory := &loginid.TypeCheckerFactory{
		Config:              loginIDConfig,
		ReservedNameChecker: reservedNameChecker,
	}
	checker := &loginid.Checker{
		Config:             loginIDConfig,
		TypeCheckerFactory: typeCheckerFactory,
	}
	normalizerFactory := &loginid.NormalizerFactory{
		Config: loginIDConfig,
	}
	clockClock := _wireSystemClockValue
	provider := &loginid.Provider{
		Store:             loginidStore,
		Config:            loginIDConfig,
		Checker:           checker,
		NormalizerFactory: normalizerFactory,
		Clock:             clockClock,
	}
	oauthStore := &oauth2.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	oauthProvider := &oauth2.Provider{
		Store: oauthStore,
		Clock: clockClock,
	}
	anonymousStore := &anonymous.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	anonymousProvider := &anonymous.Provider{
		Store: anonymousStore,
		Clock: clockClock,
	}
	serviceStore := &service2.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	passwordStore := &password.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	authenticatorConfig := appConfig.Authenticator
	authenticatorPasswordConfig := authenticatorConfig.Password
	factory := appProvider.LoggerFactory
	logger := password.NewLogger(factory)
	historyStore := &password.HistoryStore{
		Clock:       clockClock,
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	passwordChecker := password.ProvideChecker(authenticatorPasswordConfig, historyStore)
	queue := appProvider.TaskQueue
	passwordProvider := &password.Provider{
		Store:           passwordStore,
		Config:          authenticatorPasswordConfig,
		Clock:           clockClock,
		Logger:          logger,
		PasswordHistory: historyStore,
		PasswordChecker: passwordChecker,
		TaskQueue:       queue,
	}
	totpStore := &totp.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	authenticatorTOTPConfig := authenticatorConfig.TOTP
	totpProvider := &totp.Provider{
		Store:  totpStore,
		Config: authenticatorTOTPConfig,
		Clock:  clockClock,
	}
	authenticatorOOBConfig := authenticatorConfig.OOB
	oobStore := &oob.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	oobProvider := &oob.Provider{
		Config: authenticatorOOBConfig,
		Store:  oobStore,
		Clock:  clockClock,
	}
	serviceService := &service2.Service{
		Store:    serviceStore,
		Password: passwordProvider,
		TOTP:     totpProvider,
		OOBOTP:   oobProvider,
	}
	verificationLogger := verification.NewLogger(factory)
	verificationConfig := appConfig.Verification
	redisHandle := appProvider.Redis
	storeRedis := &verification.StoreRedis{
		Redis: redisHandle,
		AppID: appID,
		Clock: clockClock,
	}
	storePQ := &verification.StorePQ{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	verificationService := &verification.Service{
		Logger:     verificationLogger,
		Config:     verificationConfig,
		Clock:      clockClock,
		CodeStore:  storeRedis,
		ClaimStore: storePQ,
	}
	service3 := &service.Service{
		Authentication: authenticationConfig,
		Identity:       identityConfig,
		Store:          store,
		LoginID:        provider,
		OAuth:          oauthProvider,
		Anonymous:      anonymousProvider,
		Authenticators: serviceService,
		Verification:   verificationService,
	}
	resolveHandlerLogger := handler.NewResolveHandlerLogger(factory)
	resolveHandler := &handler.ResolveHandler{
		Identities:   service3,
		Verification: verificationService,
		Logger:       resolveHandlerLogger,
	}
	return resolveHandler
}
