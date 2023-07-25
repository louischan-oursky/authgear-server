// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package resolver

import (
	"context"
	"github.com/authgear/authgear-server/pkg/lib/audit"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator/oob"
	passkey3 "github.com/authgear/authgear-server/pkg/lib/authn/authenticator/passkey"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator/password"
	service2 "github.com/authgear/authgear-server/pkg/lib/authn/authenticator/service"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator/totp"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/anonymous"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/biometric"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/loginid"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/oauth"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/passkey"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/service"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/siwe"
	"github.com/authgear/authgear-server/pkg/lib/authn/otp"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/lib/deps"
	"github.com/authgear/authgear-server/pkg/lib/elasticsearch"
	"github.com/authgear/authgear-server/pkg/lib/endpoints"
	"github.com/authgear/authgear-server/pkg/lib/event"
	"github.com/authgear/authgear-server/pkg/lib/feature/customattrs"
	passkey2 "github.com/authgear/authgear-server/pkg/lib/feature/passkey"
	siwe2 "github.com/authgear/authgear-server/pkg/lib/feature/siwe"
	"github.com/authgear/authgear-server/pkg/lib/feature/stdattrs"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/feature/web3"
	"github.com/authgear/authgear-server/pkg/lib/healthz"
	"github.com/authgear/authgear-server/pkg/lib/hook"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/auditdb"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/globaldb"
	"github.com/authgear/authgear-server/pkg/lib/infra/middleware"
	"github.com/authgear/authgear-server/pkg/lib/lockout"
	"github.com/authgear/authgear-server/pkg/lib/meter"
	oauth2 "github.com/authgear/authgear-server/pkg/lib/oauth"
	"github.com/authgear/authgear-server/pkg/lib/oauth/oidc"
	"github.com/authgear/authgear-server/pkg/lib/oauth/pq"
	"github.com/authgear/authgear-server/pkg/lib/oauth/redis"
	"github.com/authgear/authgear-server/pkg/lib/ratelimit"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/lib/session/access"
	"github.com/authgear/authgear-server/pkg/lib/session/idpsession"
	"github.com/authgear/authgear-server/pkg/lib/translation"
	"github.com/authgear/authgear-server/pkg/lib/web"
	"github.com/authgear/authgear-server/pkg/resolver/handler"
	"github.com/authgear/authgear-server/pkg/util/clock"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/rand"
	"github.com/authgear/authgear-server/pkg/util/template"
	"net/http"
)

// Injectors from wire.go:

func newHealthzHandler(p *deps.RootProvider, w http.ResponseWriter, r *http.Request, ctx context.Context) http.Handler {
	pool := p.DatabasePool
	environmentConfig := p.EnvironmentConfig
	globalDatabaseCredentialsEnvironmentConfig := &environmentConfig.GlobalDatabase
	databaseEnvironmentConfig := &environmentConfig.DatabaseConfig
	factory := p.LoggerFactory
	handle := globaldb.NewHandle(ctx, pool, globalDatabaseCredentialsEnvironmentConfig, databaseEnvironmentConfig, factory)
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

func newPanicMiddleware(p *deps.RootProvider) httproute.Middleware {
	factory := p.LoggerFactory
	panicMiddlewareLogger := middleware.NewPanicMiddlewareLogger(factory)
	panicMiddleware := &middleware.PanicMiddleware{
		Logger: panicMiddlewareLogger,
	}
	return panicMiddleware
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

func newSessionMiddleware(p *deps.RequestProvider, idpSessionOnly bool) httproute.Middleware {
	appProvider := p.AppProvider
	appContext := appProvider.AppContext
	config := appContext.Config
	appConfig := config.AppConfig
	sessionConfig := appConfig.Session
	cookieDef := session.NewSessionCookieDef(sessionConfig)
	request := p.Request
	rootProvider := appProvider.RootProvider
	environmentConfig := rootProvider.EnvironmentConfig
	trustProxy := environmentConfig.TrustProxy
	httpConfig := appConfig.HTTP
	cookieManager := deps.NewCookieManager(request, trustProxy, httpConfig)
	contextContext := deps.ProvideRequestContext(request)
	remoteIP := deps.ProvideRemoteIP(request, trustProxy)
	userAgentString := deps.ProvideUserAgentString(request)
	appID := appConfig.ID
	handle := appProvider.Redis
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
		Context:         contextContext,
		RemoteIP:        remoteIP,
		UserAgentString: userAgentString,
		AppID:           appID,
		Redis:           handle,
		Store:           storeRedis,
		AccessEvents:    eventProvider,
		TrustProxy:      trustProxy,
		Config:          sessionConfig,
		Clock:           clock,
		Random:          rand,
	}
	resolver := &idpsession.Resolver{
		Cookies:         cookieManager,
		CookieDef:       cookieDef,
		Provider:        provider,
		RemoteIP:        remoteIP,
		UserAgentString: userAgentString,
		TrustProxy:      trustProxy,
		Clock:           clock,
	}
	oAuthConfig := appConfig.OAuth
	secretConfig := config.SecretConfig
	databaseCredentials := deps.ProvideDatabaseCredentials(secretConfig)
	sqlBuilderApp := appdb.NewSQLBuilderApp(databaseCredentials, appID)
	appdbHandle := appProvider.AppDatabase
	sqlExecutor := appdb.NewSQLExecutor(contextContext, appdbHandle)
	authorizationStore := &pq.AuthorizationStore{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	logger := redis.NewLogger(factory)
	store := &redis.Store{
		Context:     contextContext,
		Redis:       handle,
		AppID:       appID,
		Logger:      logger,
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
		Clock:       clock,
	}
	oAuthKeyMaterials := deps.ProvideOAuthKeyMaterials(secretConfig)
	httpHost := deps.ProvideHTTPHost(request, trustProxy)
	httpProto := deps.ProvideHTTPProto(request, trustProxy)
	endpointsEndpoints := &endpoints.Endpoints{
		HTTPHost:  httpHost,
		HTTPProto: httpProto,
	}
	userStore := &user.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
		Clock:       clock,
	}
	rawQueries := &user.RawQueries{
		Store: userStore,
	}
	authenticationConfig := appConfig.Authentication
	identityConfig := appConfig.Identity
	featureConfig := config.FeatureConfig
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
	manager := appContext.Resources
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
	loginidProvider := &loginid.Provider{
		Store:             loginidStore,
		Config:            loginIDConfig,
		Checker:           checker,
		NormalizerFactory: normalizerFactory,
		Clock:             clock,
	}
	oauthStore := &oauth.Store{
		SQLBuilder:     sqlBuilderApp,
		SQLExecutor:    sqlExecutor,
		IdentityConfig: identityConfig,
	}
	oauthProvider := &oauth.Provider{
		Store:          oauthStore,
		Clock:          clock,
		IdentityConfig: identityConfig,
	}
	anonymousStore := &anonymous.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	anonymousProvider := &anonymous.Provider{
		Store: anonymousStore,
		Clock: clock,
	}
	biometricStore := &biometric.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	biometricProvider := &biometric.Provider{
		Store: biometricStore,
		Clock: clock,
	}
	passkeyStore := &passkey.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	store2 := &passkey2.Store{
		Context: contextContext,
		Redis:   handle,
		AppID:   appID,
	}
	defaultLanguageTag := deps.ProvideDefaultLanguageTag(config)
	supportedLanguageTags := deps.ProvideSupportedLanguageTags(config)
	templateResolver := &template.Resolver{
		Resources:             manager,
		DefaultLanguageTag:    defaultLanguageTag,
		SupportedLanguageTags: supportedLanguageTags,
	}
	engine := &template.Engine{
		Resolver: templateResolver,
	}
	localizationConfig := appConfig.Localization
	webAppCDNHost := environmentConfig.WebAppCDNHost
	globalEmbeddedResourceManager := rootProvider.EmbeddedResources
	staticAssetResolver := &web.StaticAssetResolver{
		Context:           contextContext,
		Config:            httpConfig,
		Localization:      localizationConfig,
		HTTPProto:         httpProto,
		WebAppCDNHost:     webAppCDNHost,
		Resources:         manager,
		EmbeddedResources: globalEmbeddedResourceManager,
	}
	translationService := &translation.Service{
		Context:        contextContext,
		TemplateEngine: engine,
		StaticAssets:   staticAssetResolver,
	}
	configService := &passkey2.ConfigService{
		Request:            request,
		TrustProxy:         trustProxy,
		TranslationService: translationService,
	}
	passkeyService := &passkey2.Service{
		Store:         store2,
		ConfigService: configService,
	}
	passkeyProvider := &passkey.Provider{
		Store:   passkeyStore,
		Clock:   clock,
		Passkey: passkeyService,
	}
	siweStore := &siwe.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	web3Config := appConfig.Web3
	siweStoreRedis := &siwe2.StoreRedis{
		Context: contextContext,
		Redis:   handle,
		AppID:   appID,
		Clock:   clock,
	}
	ratelimitLogger := ratelimit.NewLogger(factory)
	storageRedis := &ratelimit.StorageRedis{
		AppID: appID,
		Redis: handle,
	}
	rateLimitsFeatureConfig := featureConfig.RateLimits
	limiter := &ratelimit.Limiter{
		Logger:  ratelimitLogger,
		Storage: storageRedis,
		Config:  rateLimitsFeatureConfig,
	}
	siweLogger := siwe2.NewLogger(factory)
	siweService := &siwe2.Service{
		RemoteIP:             remoteIP,
		HTTPConfig:           httpConfig,
		Web3Config:           web3Config,
		AuthenticationConfig: authenticationConfig,
		Clock:                clock,
		NonceStore:           siweStoreRedis,
		RateLimiter:          limiter,
		Logger:               siweLogger,
	}
	siweProvider := &siwe.Provider{
		Store: siweStore,
		Clock: clock,
		SIWE:  siweService,
	}
	serviceService := &service.Service{
		Authentication:        authenticationConfig,
		Identity:              identityConfig,
		IdentityFeatureConfig: identityFeatureConfig,
		Store:                 serviceStore,
		LoginID:               loginidProvider,
		OAuth:                 oauthProvider,
		Anonymous:             anonymousProvider,
		Biometric:             biometricProvider,
		Passkey:               passkeyProvider,
		SIWE:                  siweProvider,
	}
	store3 := &service2.Store{
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
		Clock:       clock,
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	authenticatorFeatureConfig := featureConfig.Authenticator
	passwordChecker := password.ProvideChecker(authenticatorPasswordConfig, authenticatorFeatureConfig, historyStore)
	housekeeperLogger := password.NewHousekeeperLogger(factory)
	housekeeper := &password.Housekeeper{
		Store:  historyStore,
		Logger: housekeeperLogger,
		Config: authenticatorPasswordConfig,
	}
	passwordProvider := &password.Provider{
		Store:           passwordStore,
		Config:          authenticatorPasswordConfig,
		Clock:           clock,
		Logger:          passwordLogger,
		PasswordHistory: historyStore,
		PasswordChecker: passwordChecker,
		Housekeeper:     housekeeper,
	}
	store4 := &passkey3.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	provider2 := &passkey3.Provider{
		Store:   store4,
		Clock:   clock,
		Passkey: passkeyService,
	}
	totpStore := &totp.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	authenticatorTOTPConfig := authenticatorConfig.TOTP
	totpProvider := &totp.Provider{
		Store:  totpStore,
		Config: authenticatorTOTPConfig,
		Clock:  clock,
	}
	oobStore := &oob.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	oobProvider := &oob.Provider{
		Store: oobStore,
		Clock: clock,
	}
	testModeFeatureConfig := featureConfig.TestMode
	codeStoreRedis := &otp.CodeStoreRedis{
		Redis: handle,
		AppID: appID,
		Clock: clock,
	}
	lookupStoreRedis := &otp.LookupStoreRedis{
		Redis: handle,
		AppID: appID,
		Clock: clock,
	}
	attemptTrackerRedis := &otp.AttemptTrackerRedis{
		Redis: handle,
		AppID: appID,
		Clock: clock,
	}
	otpLogger := otp.NewLogger(factory)
	otpService := &otp.Service{
		Clock:                 clock,
		AppID:                 appID,
		TestModeFeatureConfig: testModeFeatureConfig,
		RemoteIP:              remoteIP,
		CodeStore:             codeStoreRedis,
		LookupStore:           lookupStoreRedis,
		AttemptTracker:        attemptTrackerRedis,
		Logger:                otpLogger,
		RateLimiter:           limiter,
	}
	rateLimits := service2.RateLimits{
		IP:          remoteIP,
		Config:      authenticationConfig,
		RateLimiter: limiter,
	}
	authenticationLockoutConfig := authenticationConfig.Lockout
	lockoutLogger := lockout.NewLogger(factory)
	lockoutStorageRedis := &lockout.StorageRedis{
		AppID: appID,
		Redis: handle,
	}
	lockoutService := &lockout.Service{
		Logger:  lockoutLogger,
		Storage: lockoutStorageRedis,
	}
	serviceLockout := service2.Lockout{
		Config:   authenticationLockoutConfig,
		RemoteIP: remoteIP,
		Provider: lockoutService,
	}
	service3 := &service2.Service{
		Store:          store3,
		Config:         appConfig,
		Password:       passwordProvider,
		Passkey:        provider2,
		TOTP:           totpProvider,
		OOBOTP:         oobProvider,
		OTPCodeService: otpService,
		RateLimits:     rateLimits,
		Lockout:        serviceLockout,
	}
	verificationConfig := appConfig.Verification
	userProfileConfig := appConfig.UserProfile
	storePQ := &verification.StorePQ{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	verificationService := &verification.Service{
		Config:            verificationConfig,
		UserProfileConfig: userProfileConfig,
		Clock:             clock,
		ClaimStore:        storePQ,
	}
	imagesCDNHost := environmentConfig.ImagesCDNHost
	pictureTransformer := &stdattrs.PictureTransformer{
		HTTPProto:     httpProto,
		HTTPHost:      httpHost,
		ImagesCDNHost: imagesCDNHost,
	}
	serviceNoEvent := &stdattrs.ServiceNoEvent{
		UserProfileConfig: userProfileConfig,
		Identities:        serviceService,
		UserQueries:       rawQueries,
		UserStore:         userStore,
		ClaimStore:        storePQ,
		Transformer:       pictureTransformer,
	}
	customattrsServiceNoEvent := &customattrs.ServiceNoEvent{
		Config:      userProfileConfig,
		UserQueries: rawQueries,
		UserStore:   userStore,
	}
	nftIndexerAPIEndpoint := environmentConfig.NFTIndexerAPIEndpoint
	web3Service := &web3.Service{
		APIEndpoint: nftIndexerAPIEndpoint,
		Web3Config:  web3Config,
	}
	queries := &user.Queries{
		RawQueries:         rawQueries,
		Store:              userStore,
		Identities:         serviceService,
		Authenticators:     service3,
		Verification:       verificationService,
		StandardAttributes: serviceNoEvent,
		CustomAttributes:   customattrsServiceNoEvent,
		Web3:               web3Service,
	}
	idTokenIssuer := &oidc.IDTokenIssuer{
		Secrets: oAuthKeyMaterials,
		BaseURL: endpointsEndpoints,
		Users:   queries,
		Clock:   clock,
	}
	eventLogger := event.NewLogger(factory)
	sqlBuilder := appdb.NewSQLBuilder(databaseCredentials)
	storeImpl := event.NewStoreImpl(sqlBuilder, sqlExecutor)
	resolverImpl := &event.ResolverImpl{
		Users: queries,
	}
	hookLogger := hook.NewLogger(factory)
	hookConfig := appConfig.Hook
	webhookKeyMaterials := deps.ProvideWebhookKeyMaterials(secretConfig)
	webHookImpl := hook.WebHookImpl{
		Secret: webhookKeyMaterials,
	}
	syncHTTPClient := hook.NewSyncHTTPClient(hookConfig)
	asyncHTTPClient := hook.NewAsyncHTTPClient()
	eventWebHookImpl := &hook.EventWebHookImpl{
		WebHookImpl: webHookImpl,
		SyncHTTP:    syncHTTPClient,
		AsyncHTTP:   asyncHTTPClient,
	}
	denoHook := hook.DenoHook{
		Context:         contextContext,
		ResourceManager: manager,
	}
	denoEndpoint := environmentConfig.DenoEndpoint
	syncDenoClient := hook.NewSyncDenoClient(denoEndpoint, hookConfig, hookLogger)
	asyncDenoClient := hook.NewAsyncDenoClient(denoEndpoint, hookLogger)
	eventDenoHookImpl := &hook.EventDenoHookImpl{
		DenoHook:        denoHook,
		SyncDenoClient:  syncDenoClient,
		AsyncDenoClient: asyncDenoClient,
	}
	sink := &hook.Sink{
		Logger:             hookLogger,
		Config:             hookConfig,
		Clock:              clock,
		EventWebHook:       eventWebHookImpl,
		EventDenoHook:      eventDenoHookImpl,
		StandardAttributes: serviceNoEvent,
		CustomAttributes:   customattrsServiceNoEvent,
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
	elasticsearchLogger := elasticsearch.NewLogger(factory)
	elasticsearchCredentials := deps.ProvideElasticsearchCredentials(secretConfig)
	client := elasticsearch.NewClient(elasticsearchCredentials)
	queue := appProvider.TaskQueue
	elasticsearchService := elasticsearch.Service{
		AppID:     appID,
		Client:    client,
		Users:     queries,
		OAuth:     oauthStore,
		LoginID:   loginidStore,
		TaskQueue: queue,
	}
	elasticsearchSink := &elasticsearch.Sink{
		Logger:   elasticsearchLogger,
		Service:  elasticsearchService,
		Database: appdbHandle,
	}
	eventService := event.NewService(contextContext, appID, remoteIP, userAgentString, eventLogger, appdbHandle, clock, localizationConfig, storeImpl, resolverImpl, sink, auditSink, elasticsearchSink)
	accessTokenEncoding := &oauth2.AccessTokenEncoding{
		Secrets:    oAuthKeyMaterials,
		Clock:      clock,
		UserClaims: idTokenIssuer,
		BaseURL:    endpointsEndpoints,
		Events:     eventService,
	}
	offlineGrantService := oauth2.OfflineGrantService{
		OAuthConfig: oAuthConfig,
		Clock:       clock,
		IDPSessions: provider,
	}
	oauthResolver := &oauth2.Resolver{
		RemoteIP:            remoteIP,
		UserAgentString:     userAgentString,
		OAuthConfig:         oAuthConfig,
		Authorizations:      authorizationStore,
		AccessGrants:        store,
		OfflineGrants:       store,
		AppSessions:         store,
		AccessTokenDecoder:  accessTokenEncoding,
		Sessions:            provider,
		Cookies:             cookieManager,
		Clock:               clock,
		OfflineGrantService: offlineGrantService,
	}
	middlewareLogger := session.NewMiddlewareLogger(factory)
	analyticredisHandle := appProvider.AnalyticRedis
	meterStoreRedisLogger := meter.NewStoreRedisLogger(factory)
	writeStoreRedis := &meter.WriteStoreRedis{
		Context: contextContext,
		Redis:   analyticredisHandle,
		AppID:   appID,
		Clock:   clock,
		Logger:  meterStoreRedisLogger,
	}
	meterService := &meter.Service{
		Counter: writeStoreRedis,
	}
	sessionMiddleware := &session.Middleware{
		SessionCookie:              cookieDef,
		Cookies:                    cookieManager,
		IDPSessionResolver:         resolver,
		AccessTokenSessionResolver: oauthResolver,
		AccessEvents:               eventProvider,
		Users:                      queries,
		Database:                   appdbHandle,
		Logger:                     middlewareLogger,
		MeterService:               meterService,
		IDPSessionOnly:             idpSessionOnly,
	}
	return sessionMiddleware
}

var (
	_wireSystemClockValue = clock.NewSystemClock()
	_wireRandValue        = idpsession.Rand(rand.SecureRand)
)

func newSessionResolveHandler(p *deps.RequestProvider) http.Handler {
	appProvider := p.AppProvider
	handle := appProvider.AppDatabase
	appContext := appProvider.AppContext
	config := appContext.Config
	appConfig := config.AppConfig
	authenticationConfig := appConfig.Authentication
	identityConfig := appConfig.Identity
	featureConfig := config.FeatureConfig
	identityFeatureConfig := featureConfig.Identity
	secretConfig := config.SecretConfig
	databaseCredentials := deps.ProvideDatabaseCredentials(secretConfig)
	appID := appConfig.ID
	sqlBuilderApp := appdb.NewSQLBuilderApp(databaseCredentials, appID)
	request := p.Request
	contextContext := deps.ProvideRequestContext(request)
	sqlExecutor := appdb.NewSQLExecutor(contextContext, handle)
	store := &service.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	loginidStore := &loginid.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	loginIDConfig := identityConfig.LoginID
	manager := appContext.Resources
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
		SQLBuilder:     sqlBuilderApp,
		SQLExecutor:    sqlExecutor,
		IdentityConfig: identityConfig,
	}
	oauthProvider := &oauth.Provider{
		Store:          oauthStore,
		Clock:          clockClock,
		IdentityConfig: identityConfig,
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
	passkeyStore := &passkey.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	appredisHandle := appProvider.Redis
	store2 := &passkey2.Store{
		Context: contextContext,
		Redis:   appredisHandle,
		AppID:   appID,
	}
	rootProvider := appProvider.RootProvider
	environmentConfig := rootProvider.EnvironmentConfig
	trustProxy := environmentConfig.TrustProxy
	defaultLanguageTag := deps.ProvideDefaultLanguageTag(config)
	supportedLanguageTags := deps.ProvideSupportedLanguageTags(config)
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
	httpProto := deps.ProvideHTTPProto(request, trustProxy)
	webAppCDNHost := environmentConfig.WebAppCDNHost
	globalEmbeddedResourceManager := rootProvider.EmbeddedResources
	staticAssetResolver := &web.StaticAssetResolver{
		Context:           contextContext,
		Config:            httpConfig,
		Localization:      localizationConfig,
		HTTPProto:         httpProto,
		WebAppCDNHost:     webAppCDNHost,
		Resources:         manager,
		EmbeddedResources: globalEmbeddedResourceManager,
	}
	translationService := &translation.Service{
		Context:        contextContext,
		TemplateEngine: engine,
		StaticAssets:   staticAssetResolver,
	}
	configService := &passkey2.ConfigService{
		Request:            request,
		TrustProxy:         trustProxy,
		TranslationService: translationService,
	}
	passkeyService := &passkey2.Service{
		Store:         store2,
		ConfigService: configService,
	}
	passkeyProvider := &passkey.Provider{
		Store:   passkeyStore,
		Clock:   clockClock,
		Passkey: passkeyService,
	}
	siweStore := &siwe.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	remoteIP := deps.ProvideRemoteIP(request, trustProxy)
	web3Config := appConfig.Web3
	storeRedis := &siwe2.StoreRedis{
		Context: contextContext,
		Redis:   appredisHandle,
		AppID:   appID,
		Clock:   clockClock,
	}
	factory := appProvider.LoggerFactory
	logger := ratelimit.NewLogger(factory)
	storageRedis := &ratelimit.StorageRedis{
		AppID: appID,
		Redis: appredisHandle,
	}
	rateLimitsFeatureConfig := featureConfig.RateLimits
	limiter := &ratelimit.Limiter{
		Logger:  logger,
		Storage: storageRedis,
		Config:  rateLimitsFeatureConfig,
	}
	siweLogger := siwe2.NewLogger(factory)
	siweService := &siwe2.Service{
		RemoteIP:             remoteIP,
		HTTPConfig:           httpConfig,
		Web3Config:           web3Config,
		AuthenticationConfig: authenticationConfig,
		Clock:                clockClock,
		NonceStore:           storeRedis,
		RateLimiter:          limiter,
		Logger:               siweLogger,
	}
	siweProvider := &siwe.Provider{
		Store: siweStore,
		Clock: clockClock,
		SIWE:  siweService,
	}
	serviceService := &service.Service{
		Authentication:        authenticationConfig,
		Identity:              identityConfig,
		IdentityFeatureConfig: identityFeatureConfig,
		Store:                 store,
		LoginID:               provider,
		OAuth:                 oauthProvider,
		Anonymous:             anonymousProvider,
		Biometric:             biometricProvider,
		Passkey:               passkeyProvider,
		SIWE:                  siweProvider,
	}
	verificationConfig := appConfig.Verification
	userProfileConfig := appConfig.UserProfile
	storePQ := &verification.StorePQ{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	verificationService := &verification.Service{
		Config:            verificationConfig,
		UserProfileConfig: userProfileConfig,
		Clock:             clockClock,
		ClaimStore:        storePQ,
	}
	resolveHandlerLogger := handler.NewResolveHandlerLogger(factory)
	userStore := &user.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
		Clock:       clockClock,
	}
	rawQueries := &user.RawQueries{
		Store: userStore,
	}
	serviceStore := &service2.Store{
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
	authenticatorFeatureConfig := featureConfig.Authenticator
	passwordChecker := password.ProvideChecker(authenticatorPasswordConfig, authenticatorFeatureConfig, historyStore)
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
	store3 := &passkey3.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	provider2 := &passkey3.Provider{
		Store:   store3,
		Clock:   clockClock,
		Passkey: passkeyService,
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
	oobStore := &oob.Store{
		SQLBuilder:  sqlBuilderApp,
		SQLExecutor: sqlExecutor,
	}
	oobProvider := &oob.Provider{
		Store: oobStore,
		Clock: clockClock,
	}
	testModeFeatureConfig := featureConfig.TestMode
	codeStoreRedis := &otp.CodeStoreRedis{
		Redis: appredisHandle,
		AppID: appID,
		Clock: clockClock,
	}
	lookupStoreRedis := &otp.LookupStoreRedis{
		Redis: appredisHandle,
		AppID: appID,
		Clock: clockClock,
	}
	attemptTrackerRedis := &otp.AttemptTrackerRedis{
		Redis: appredisHandle,
		AppID: appID,
		Clock: clockClock,
	}
	otpLogger := otp.NewLogger(factory)
	otpService := &otp.Service{
		Clock:                 clockClock,
		AppID:                 appID,
		TestModeFeatureConfig: testModeFeatureConfig,
		RemoteIP:              remoteIP,
		CodeStore:             codeStoreRedis,
		LookupStore:           lookupStoreRedis,
		AttemptTracker:        attemptTrackerRedis,
		Logger:                otpLogger,
		RateLimiter:           limiter,
	}
	rateLimits := service2.RateLimits{
		IP:          remoteIP,
		Config:      authenticationConfig,
		RateLimiter: limiter,
	}
	authenticationLockoutConfig := authenticationConfig.Lockout
	lockoutLogger := lockout.NewLogger(factory)
	lockoutStorageRedis := &lockout.StorageRedis{
		AppID: appID,
		Redis: appredisHandle,
	}
	lockoutService := &lockout.Service{
		Logger:  lockoutLogger,
		Storage: lockoutStorageRedis,
	}
	serviceLockout := service2.Lockout{
		Config:   authenticationLockoutConfig,
		RemoteIP: remoteIP,
		Provider: lockoutService,
	}
	service3 := &service2.Service{
		Store:          serviceStore,
		Config:         appConfig,
		Password:       passwordProvider,
		Passkey:        provider2,
		TOTP:           totpProvider,
		OOBOTP:         oobProvider,
		OTPCodeService: otpService,
		RateLimits:     rateLimits,
		Lockout:        serviceLockout,
	}
	httpHost := deps.ProvideHTTPHost(request, trustProxy)
	imagesCDNHost := environmentConfig.ImagesCDNHost
	pictureTransformer := &stdattrs.PictureTransformer{
		HTTPProto:     httpProto,
		HTTPHost:      httpHost,
		ImagesCDNHost: imagesCDNHost,
	}
	serviceNoEvent := &stdattrs.ServiceNoEvent{
		UserProfileConfig: userProfileConfig,
		Identities:        serviceService,
		UserQueries:       rawQueries,
		UserStore:         userStore,
		ClaimStore:        storePQ,
		Transformer:       pictureTransformer,
	}
	customattrsServiceNoEvent := &customattrs.ServiceNoEvent{
		Config:      userProfileConfig,
		UserQueries: rawQueries,
		UserStore:   userStore,
	}
	nftIndexerAPIEndpoint := environmentConfig.NFTIndexerAPIEndpoint
	web3Service := &web3.Service{
		APIEndpoint: nftIndexerAPIEndpoint,
		Web3Config:  web3Config,
	}
	queries := &user.Queries{
		RawQueries:         rawQueries,
		Store:              userStore,
		Identities:         serviceService,
		Authenticators:     service3,
		Verification:       verificationService,
		StandardAttributes: serviceNoEvent,
		CustomAttributes:   customattrsServiceNoEvent,
		Web3:               web3Service,
	}
	resolveHandler := &handler.ResolveHandler{
		Database:     handle,
		Identities:   serviceService,
		Verification: verificationService,
		Logger:       resolveHandlerLogger,
		Users:        queries,
	}
	return resolveHandler
}
