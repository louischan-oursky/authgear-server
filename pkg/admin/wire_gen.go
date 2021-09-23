// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package admin

import (
	"context"
	facade2 "github.com/authgear/authgear-server/pkg/admin/facade"
	"github.com/authgear/authgear-server/pkg/admin/graphql"
	"github.com/authgear/authgear-server/pkg/admin/loader"
	service3 "github.com/authgear/authgear-server/pkg/admin/service"
	"github.com/authgear/authgear-server/pkg/admin/transport"
	"github.com/authgear/authgear-server/pkg/lib/admin/authz"
	"github.com/authgear/authgear-server/pkg/lib/audit"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticationinfo"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator/oob"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator/password"
	service2 "github.com/authgear/authgear-server/pkg/lib/authn/authenticator/service"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator/totp"
	"github.com/authgear/authgear-server/pkg/lib/authn/challenge"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/anonymous"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/biometric"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/loginid"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/oauth"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/service"
	"github.com/authgear/authgear-server/pkg/lib/authn/mfa"
	"github.com/authgear/authgear-server/pkg/lib/authn/otp"
	"github.com/authgear/authgear-server/pkg/lib/authn/sso"
	"github.com/authgear/authgear-server/pkg/lib/authn/stdattrs"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/deps"
	"github.com/authgear/authgear-server/pkg/lib/elasticsearch"
	"github.com/authgear/authgear-server/pkg/lib/event"
	"github.com/authgear/authgear-server/pkg/lib/facade"
	"github.com/authgear/authgear-server/pkg/lib/feature/forgotpassword"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/feature/welcomemessage"
	"github.com/authgear/authgear-server/pkg/lib/healthz"
	"github.com/authgear/authgear-server/pkg/lib/hook"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/auditdb"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/globaldb"
	"github.com/authgear/authgear-server/pkg/lib/infra/middleware"
	"github.com/authgear/authgear-server/pkg/lib/interaction"
	"github.com/authgear/authgear-server/pkg/lib/nonce"
	oauth2 "github.com/authgear/authgear-server/pkg/lib/oauth"
	"github.com/authgear/authgear-server/pkg/lib/oauth/pq"
	"github.com/authgear/authgear-server/pkg/lib/oauth/redis"
	"github.com/authgear/authgear-server/pkg/lib/ratelimit"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/lib/session/access"
	"github.com/authgear/authgear-server/pkg/lib/session/idpsession"
	"github.com/authgear/authgear-server/pkg/lib/translation"
	"github.com/authgear/authgear-server/pkg/lib/web"
	"github.com/authgear/authgear-server/pkg/util/clock"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/rand"
	"github.com/authgear/authgear-server/pkg/util/template"
	"net/http"
)

// Injectors from wire.go:

func newPanicMiddleware(p *deps.RootProvider) httproute.Middleware {
	factory := p.LoggerFactory
	panicMiddlewareLogger := middleware.NewPanicMiddlewareLogger(factory)
	panicMiddleware := &middleware.PanicMiddleware{
		Logger: panicMiddlewareLogger,
	}
	return panicMiddleware
}

func newHealthzHandler(p *deps.RootProvider, w http.ResponseWriter, r *http.Request, ctx context.Context) http.Handler {
	pool := p.DatabasePool
	environmentConfig := p.EnvironmentConfig
	databaseEnvironmentConfig := &environmentConfig.Database
	factory := p.LoggerFactory
	handle := globaldb.NewHandle(ctx, pool, databaseEnvironmentConfig, factory)
	sqlExecutor := globaldb.NewSQLExecutor(ctx, handle)
	handlerLogger := healthz.NewHandlerLogger(factory)
	handler := &healthz.Handler{
		Context:        ctx,
		GlobalDatabase: handle,
		GlobalExecutor: sqlExecutor,
		Logger:         handlerLogger,
	}
	return handler
}

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

func newBodyLimitMiddleware(p *deps.RootProvider) httproute.Middleware {
	bodyLimitMiddleware := &middleware.BodyLimitMiddleware{}
	return bodyLimitMiddleware
}

func newAuthorizationMiddleware(p *deps.RequestProvider, auth config.AdminAPIAuth) httproute.Middleware {
	appProvider := p.AppProvider
	factory := appProvider.LoggerFactory
	logger := authz.NewLogger(factory)
	configConfig := appProvider.Config
	appConfig := configConfig.AppConfig
	appID := appConfig.ID
	secretConfig := configConfig.SecretConfig
	adminAPIAuthKey := deps.ProvideAdminAPIAuthKeyMaterials(secretConfig)
	clock := _wireSystemClockValue
	authzMiddleware := &authz.Middleware{
		Logger:  logger,
		Auth:    auth,
		AppID:   appID,
		AuthKey: adminAPIAuthKey,
		Clock:   clock,
	}
	return authzMiddleware
}

var (
	_wireSystemClockValue = clock.NewSystemClock()
)

func newGraphQLHandler(p *deps.RequestProvider) http.Handler {
	appProvider := p.AppProvider
	factory := appProvider.LoggerFactory
	logger := graphql.NewLogger(factory)
	configConfig := appProvider.Config
	secretConfig := configConfig.SecretConfig
	databaseCredentials := deps.ProvideDatabaseCredentials(secretConfig)
	appConfig := configConfig.AppConfig
	appID := appConfig.ID
	sqlBuilderApp := appdb.NewSQLBuilderApp(databaseCredentials, appID)
	request := p.Request
	contextContext := deps.ProvideRequestContext(request)
	handle := appProvider.AppDatabase
	sqlExecutor := appdb.NewSQLExecutor(contextContext, handle)
	store := &user.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	rawQueries := &user.RawQueries{
		Store: store,
	}
	authenticationConfig := appConfig.Authentication
	identityConfig := appConfig.Identity
	featureConfig := configConfig.FeatureConfig
	identityFeatureConfig := featureConfig.Identity
	serviceStore := &service.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	loginidStore := &loginid.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	loginIDConfig := identityConfig.LoginID
	manager := appProvider.Resources
	typeCheckerFactory := &loginid.TypeCheckerFactory{
		Config:    loginIDConfig,
		Resources: manager,
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
	oauthStore := &oauth.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	oauthProvider := &oauth.Provider{
		Store: oauthStore,
		Clock: clockClock,
	}
	anonymousStore := &anonymous.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	anonymousProvider := &anonymous.Provider{
		Store: anonymousStore,
		Clock: clockClock,
	}
	biometricStore := &biometric.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	biometricProvider := &biometric.Provider{
		Store: biometricStore,
		Clock: clockClock,
	}
	serviceService := &service.Service{
		Authentication:        authenticationConfig,
		Identity:              identityConfig,
		IdentityFeatureConfig: identityFeatureConfig,
		Store:                 serviceStore,
		LoginID:               provider,
		OAuth:                 oauthProvider,
		Anonymous:             anonymousProvider,
		Biometric:             biometricProvider,
	}
	store2 := &service2.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	passwordStore := &password.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	authenticatorConfig := appConfig.Authenticator
	authenticatorPasswordConfig := authenticatorConfig.Password
	passwordLogger := password.NewLogger(factory)
	historyStore := &password.HistoryStore{
		Clock:       clockClock,
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	passwordChecker := password.ProvideChecker(authenticatorPasswordConfig, historyStore)
	housekeeperLogger := password.NewHousekeeperLogger(factory)
	housekeeper := &password.Housekeeper{
		Store:  historyStore,
		Logger: housekeeperLogger,
		Config: authenticatorPasswordConfig,
	}
	passwordProvider := &password.Provider{
		Store:           passwordStore,
		Config:          authenticatorPasswordConfig,
		Clock:           clockClock,
		Logger:          passwordLogger,
		PasswordHistory: historyStore,
		PasswordChecker: passwordChecker,
		Housekeeper:     housekeeper,
	}
	totpStore := &totp.Store{
		SQLBuilder:  sqlBuilderApp,
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
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	appredisHandle := appProvider.Redis
	storeRedis := &oob.StoreRedis{
		Redis: appredisHandle,
		AppID: appID,
		Clock: clockClock,
	}
	oobLogger := oob.NewLogger(factory)
	oobProvider := &oob.Provider{
		Config:    authenticatorOOBConfig,
		Store:     oobStore,
		CodeStore: storeRedis,
		Clock:     clockClock,
		Logger:    oobLogger,
	}
	ratelimitLogger := ratelimit.NewLogger(factory)
	storageRedis := &ratelimit.StorageRedis{
		AppID: appID,
		Redis: appredisHandle,
	}
	limiter := &ratelimit.Limiter{
		Logger:  ratelimitLogger,
		Storage: storageRedis,
		Clock:   clockClock,
	}
	service4 := &service2.Service{
		Store:       store2,
		Password:    passwordProvider,
		TOTP:        totpProvider,
		OOBOTP:      oobProvider,
		RateLimiter: limiter,
	}
	verificationLogger := verification.NewLogger(factory)
	verificationConfig := appConfig.Verification
	rootProvider := appProvider.RootProvider
	environmentConfig := rootProvider.EnvironmentConfig
	trustProxy := environmentConfig.TrustProxy
	verificationStoreRedis := &verification.StoreRedis{
		Redis: appredisHandle,
		AppID: appID,
		Clock: clockClock,
	}
	storePQ := &verification.StorePQ{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	verificationService := &verification.Service{
		Request:     request,
		Logger:      verificationLogger,
		Config:      verificationConfig,
		TrustProxy:  trustProxy,
		Clock:       clockClock,
		CodeStore:   verificationStoreRedis,
		ClaimStore:  storePQ,
		RateLimiter: limiter,
	}
	storeDeviceTokenRedis := &mfa.StoreDeviceTokenRedis{
		Redis: appredisHandle,
		AppID: appID,
		Clock: clockClock,
	}
	storeRecoveryCodePQ := &mfa.StoreRecoveryCodePQ{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	mfaService := &mfa.Service{
		DeviceTokens:  storeDeviceTokenRedis,
		RecoveryCodes: storeRecoveryCodePQ,
		Clock:         clockClock,
		Config:        authenticationConfig,
		RateLimiter:   limiter,
	}
	defaultLanguageTag := deps.ProvideDefaultLanguageTag(configConfig)
	supportedLanguageTags := deps.ProvideSupportedLanguageTags(configConfig)
	resolver := &template.Resolver{
		Resources:             manager,
		DefaultLanguageTag:    defaultLanguageTag,
		SupportedLanguageTags: supportedLanguageTags,
	}
	engine := &template.Engine{
		Resolver: resolver,
	}
	httpConfig := appConfig.HTTP
	localizationConfig := appConfig.Localization
	staticAssetURLPrefix := environmentConfig.StaticAssetURLPrefix
	staticAssetResolver := &web.StaticAssetResolver{
		Context:            contextContext,
		Config:             httpConfig,
		Localization:       localizationConfig,
		StaticAssetsPrefix: staticAssetURLPrefix,
		Resources:          manager,
	}
	translationService := &translation.Service{
		Context:        contextContext,
		TemplateEngine: engine,
		StaticAssets:   staticAssetResolver,
	}
	welcomeMessageConfig := appConfig.WelcomeMessage
	queue := appProvider.TaskQueue
	eventLogger := event.NewLogger(factory)
	sqlBuilder := appdb.NewSQLBuilder(databaseCredentials)
	storeImpl := &event.StoreImpl{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	hookLogger := hook.NewLogger(factory)
	hookConfig := appConfig.Hook
	webhookKeyMaterials := deps.ProvideWebhookKeyMaterials(secretConfig)
	syncHTTPClient := hook.NewSyncHTTPClient(hookConfig)
	asyncHTTPClient := hook.NewAsyncHTTPClient()
	deliverer := &hook.Deliverer{
		Config:    hookConfig,
		Secret:    webhookKeyMaterials,
		Clock:     clockClock,
		SyncHTTP:  syncHTTPClient,
		AsyncHTTP: asyncHTTPClient,
	}
	sink := &hook.Sink{
		Logger:    hookLogger,
		Deliverer: deliverer,
	}
	auditLogger := audit.NewLogger(factory)
	writeHandle := appProvider.AuditWriteDatabase
	auditDatabaseCredentials := deps.ProvideAuditDatabaseCredentials(secretConfig)
	auditdbSQLBuilderApp := auditdb.NewSQLBuilderApp(auditDatabaseCredentials, appID)
	writeSQLExecutor := auditdb.NewWriteSQLExecutor(contextContext, writeHandle)
	writeStore := &audit.WriteStore{
		SQLBuilder:  auditdbSQLBuilderApp,
		SQLExecutor: writeSQLExecutor,
	}
	auditSink := &audit.Sink{
		Logger:   auditLogger,
		Database: writeHandle,
		Store:    writeStore,
	}
	eventService := event.NewService(contextContext, request, trustProxy, eventLogger, handle, clockClock, localizationConfig, storeImpl, sink, auditSink)
	welcomemessageProvider := &welcomemessage.Provider{
		Translation:          translationService,
		RateLimiter:          limiter,
		WelcomeMessageConfig: welcomeMessageConfig,
		TaskQueue:            queue,
		Events:               eventService,
	}
	rawCommands := &user.RawCommands{
		Store:                  store,
		Clock:                  clockClock,
		WelcomeMessageProvider: welcomemessageProvider,
	}
	authorizationStore := &pq.AuthorizationStore{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	storeRedisLogger := idpsession.NewStoreRedisLogger(factory)
	idpsessionStoreRedis := &idpsession.StoreRedis{
		Redis:  appredisHandle,
		AppID:  appID,
		Clock:  clockClock,
		Logger: storeRedisLogger,
	}
	sessionConfig := appConfig.Session
	cookieManager := deps.NewCookieManager(request, trustProxy, httpConfig)
	cookieDef := session.NewSessionCookieDef(sessionConfig)
	idpsessionManager := &idpsession.Manager{
		Store:     idpsessionStoreRedis,
		Clock:     clockClock,
		Config:    sessionConfig,
		Cookies:   cookieManager,
		CookieDef: cookieDef,
	}
	redisLogger := redis.NewLogger(factory)
	redisStore := &redis.Store{
		Context:     contextContext,
		Redis:       appredisHandle,
		AppID:       appID,
		Logger:      redisLogger,
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
		Clock:       clockClock,
	}
	oAuthConfig := appConfig.OAuth
	sessionManager := &oauth2.SessionManager{
		Store:  redisStore,
		Clock:  clockClock,
		Config: oAuthConfig,
	}
	coordinator := &facade.Coordinator{
		Identities:      serviceService,
		Authenticators:  service4,
		Verification:    verificationService,
		MFA:             mfaService,
		UserCommands:    rawCommands,
		UserQueries:     rawQueries,
		PasswordHistory: historyStore,
		OAuth:           authorizationStore,
		IDPSessions:     idpsessionManager,
		OAuthSessions:   sessionManager,
		IdentityConfig:  identityConfig,
	}
	identityFacade := facade.IdentityFacade{
		Coordinator: coordinator,
	}
	authenticatorFacade := facade.AuthenticatorFacade{
		Coordinator: coordinator,
	}
	queries := &user.Queries{
		RawQueries:     rawQueries,
		Store:          store,
		Identities:     identityFacade,
		Authenticators: authenticatorFacade,
		Verification:   verificationService,
	}
	userLoader := loader.NewUserLoader(queries)
	identityLoader := loader.NewIdentityLoader(serviceService)
	authenticatorLoader := loader.NewAuthenticatorLoader(service4)
	readHandle := appProvider.AuditReadDatabase
	readSQLExecutor := auditdb.NewReadSQLExecutor(contextContext, readHandle)
	readStore := &audit.ReadStore{
		SQLBuilder:  auditdbSQLBuilderApp,
		SQLExecutor: readSQLExecutor,
	}
	query := &audit.Query{
		Database: readHandle,
		Store:    readStore,
	}
	auditLogLoader := loader.NewAuditLogLoader(query)
	elasticsearchCredentials := deps.ProvideElasticsearchCredentials(secretConfig)
	client := elasticsearch.NewClient(elasticsearchCredentials)
	elasticsearchService := &elasticsearch.Service{
		AppID:     appID,
		Client:    client,
		Users:     store,
		OAuth:     oauthStore,
		LoginID:   loginidStore,
		TaskQueue: queue,
	}
	commands := &user.Commands{
		RawCommands:  rawCommands,
		Events:       eventService,
		Verification: verificationService,
	}
	userProvider := &user.Provider{
		Commands: commands,
		Queries:  queries,
	}
	userFacade := &facade.UserFacade{
		UserProvider: userProvider,
		Coordinator:  coordinator,
	}
	interactionLogger := interaction.NewLogger(factory)
	webEndpoints := &WebEndpoints{}
	messageSender := &otp.MessageSender{
		Translation: translationService,
		Endpoints:   webEndpoints,
		RateLimiter: limiter,
		TaskQueue:   queue,
		Events:      eventService,
	}
	codeSender := &oob.CodeSender{
		OTPMessageSender: messageSender,
	}
	oAuthClientCredentials := deps.ProvideOAuthClientCredentials(secretConfig)
	normalizer := &stdattrs.Normalizer{
		LoginIDNormalizerFactory: normalizerFactory,
	}
	oAuthProviderFactory := &sso.OAuthProviderFactory{
		Endpoints:                    webEndpoints,
		IdentityConfig:               identityConfig,
		Credentials:                  oAuthClientCredentials,
		RedirectURL:                  webEndpoints,
		Clock:                        clockClock,
		WechatURLProvider:            webEndpoints,
		StandardAttributesNormalizer: normalizer,
	}
	forgotPasswordConfig := appConfig.ForgotPassword
	forgotpasswordStore := &forgotpassword.Store{
		Context: contextContext,
		AppID:   appID,
		Redis:   appredisHandle,
	}
	providerLogger := forgotpassword.NewProviderLogger(factory)
	forgotpasswordProvider := &forgotpassword.Provider{
		Request:        request,
		Translation:    translationService,
		Config:         forgotPasswordConfig,
		TrustProxy:     trustProxy,
		Store:          forgotpasswordStore,
		Clock:          clockClock,
		URLs:           webEndpoints,
		TaskQueue:      queue,
		Logger:         providerLogger,
		Identities:     identityFacade,
		Authenticators: authenticatorFacade,
		RateLimiter:    limiter,
		FeatureConfig:  featureConfig,
		Events:         eventService,
	}
	verificationCodeSender := &verification.CodeSender{
		OTPMessageSender: messageSender,
		WebAppURLs:       webEndpoints,
	}
	responseWriter := p.ResponseWriter
	nonceService := &nonce.Service{
		Cookies:        cookieManager,
		Request:        request,
		ResponseWriter: responseWriter,
	}
	challengeProvider := &challenge.Provider{
		Redis: appredisHandle,
		AppID: appID,
		Clock: clockClock,
	}
	authenticationinfoStoreRedis := &authenticationinfo.StoreRedis{
		Context: contextContext,
		Redis:   appredisHandle,
		AppID:   appID,
	}
	eventStoreRedis := &access.EventStoreRedis{
		Redis: appredisHandle,
		AppID: appID,
	}
	eventProvider := &access.EventProvider{
		Store: eventStoreRedis,
	}
	rand := _wireRandValue
	idpsessionProvider := &idpsession.Provider{
		Context:      contextContext,
		Request:      request,
		AppID:        appID,
		Redis:        appredisHandle,
		Store:        idpsessionStoreRedis,
		AccessEvents: eventProvider,
		TrustProxy:   trustProxy,
		Config:       sessionConfig,
		Clock:        clockClock,
		Random:       rand,
	}
	mfaCookieDef := mfa.NewDeviceTokenCookieDef(authenticationConfig)
	interactionContext := &interaction.Context{
		Request:                   request,
		Database:                  sqlExecutor,
		Clock:                     clockClock,
		Config:                    appConfig,
		FeatureConfig:             featureConfig,
		TrustProxy:                trustProxy,
		Identities:                identityFacade,
		Authenticators:            authenticatorFacade,
		AnonymousIdentities:       anonymousProvider,
		BiometricIdentities:       biometricProvider,
		OOBAuthenticators:         oobProvider,
		OOBCodeSender:             codeSender,
		OAuthProviderFactory:      oAuthProviderFactory,
		MFA:                       mfaService,
		ForgotPassword:            forgotpasswordProvider,
		ResetPassword:             forgotpasswordProvider,
		LoginIDNormalizerFactory:  normalizerFactory,
		Verification:              verificationService,
		VerificationCodeSender:    verificationCodeSender,
		RateLimiter:               limiter,
		Nonces:                    nonceService,
		Search:                    elasticsearchService,
		Challenges:                challengeProvider,
		Users:                     userProvider,
		Events:                    eventService,
		CookieManager:             cookieManager,
		AuthenticationInfoService: authenticationinfoStoreRedis,
		Sessions:                  idpsessionProvider,
		SessionManager:            idpsessionManager,
		SessionCookie:             cookieDef,
		MFADeviceTokenCookie:      mfaCookieDef,
	}
	interactionStoreRedis := &interaction.StoreRedis{
		Redis: appredisHandle,
		AppID: appID,
	}
	interactionService := &interaction.Service{
		Logger:  interactionLogger,
		Context: interactionContext,
		Store:   interactionStoreRedis,
	}
	serviceInteractionService := &service3.InteractionService{
		Graph: interactionService,
	}
	facadeUserFacade := &facade2.UserFacade{
		UserSearchService: elasticsearchService,
		Users:             userFacade,
		Interaction:       serviceInteractionService,
	}
	auditLogFeatureConfig := featureConfig.AuditLog
	auditLogFacade := &facade2.AuditLogFacade{
		AuditLogQuery:         query,
		Clock:                 clockClock,
		AuditLogFeatureConfig: auditLogFeatureConfig,
	}
	facadeIdentityFacade := &facade2.IdentityFacade{
		Identities:  serviceService,
		Interaction: serviceInteractionService,
	}
	facadeAuthenticatorFacade := &facade2.AuthenticatorFacade{
		Authenticators: service4,
		Interaction:    serviceInteractionService,
	}
	verificationFacade := &facade2.VerificationFacade{
		Verification: verificationService,
	}
	manager2 := &session.Manager{
		Users:               queries,
		IDPSessions:         idpsessionManager,
		AccessTokenSessions: sessionManager,
		Events:              eventService,
	}
	sessionFacade := &facade2.SessionFacade{
		Sessions: manager2,
	}
	graphqlContext := &graphql.Context{
		GQLLogger:           logger,
		Users:               userLoader,
		Identities:          identityLoader,
		Authenticators:      authenticatorLoader,
		AuditLogs:           auditLogLoader,
		UserFacade:          facadeUserFacade,
		AuditLogFacade:      auditLogFacade,
		IdentityFacade:      facadeIdentityFacade,
		AuthenticatorFacade: facadeAuthenticatorFacade,
		VerificationFacade:  verificationFacade,
		SessionFacade:       sessionFacade,
	}
	graphQLHandler := &transport.GraphQLHandler{
		GraphQLContext: graphqlContext,
		AppDatabase:    handle,
		AuditDatabase:  readHandle,
	}
	return graphQLHandler
}

var (
	_wireRandValue = idpsession.Rand(rand.SecureRand)
)
