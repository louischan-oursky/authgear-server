// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package loginid

import (
	"github.com/skygeario/skygear-server/pkg/auth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/audit"
	auth2 "github.com/skygeario/skygear-server/pkg/auth/dependency/auth"
	redis3 "github.com/skygeario/skygear-server/pkg/auth/dependency/auth/redis"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/authenticator/bearertoken"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/authenticator/oob"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/authenticator/password"
	provider2 "github.com/skygeario/skygear-server/pkg/auth/dependency/authenticator/provider"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/authenticator/recoverycode"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/authenticator/totp"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/challenge"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/hook"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/identity/anonymous"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/identity/loginid"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/identity/oauth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/identity/provider"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/interaction"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/interaction/flows"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/interaction/redis"
	oauth2 "github.com/skygeario/skygear-server/pkg/auth/dependency/oauth"
	handler2 "github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/handler"
	pq3 "github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/pq"
	redis2 "github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/redis"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/oidc"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/passwordhistory/pq"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/session"
	redis4 "github.com/skygeario/skygear-server/pkg/auth/dependency/session/redis"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/urlprefix"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/userprofile"
	"github.com/skygeario/skygear-server/pkg/core/async"
	pq2 "github.com/skygeario/skygear-server/pkg/core/auth/authinfo/pq"
	"github.com/skygeario/skygear-server/pkg/core/db"
	"github.com/skygeario/skygear-server/pkg/core/handler"
	"github.com/skygeario/skygear-server/pkg/core/logging"
	"github.com/skygeario/skygear-server/pkg/core/time"
	"github.com/skygeario/skygear-server/pkg/core/validation"
	"net/http"
)

// Injectors from wire.go:

func newAddLoginIDHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	validator := auth.ProvideValidator(m)
	context := auth.ProvideContext(r)
	requestID := auth.ProvideLoggingRequestID(r)
	tenantConfiguration := auth.ProvideTenantConfig(context, m)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	requireAuthz := handler.NewRequireAuthzFactory(factory)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	timeProvider := time.NewProvider()
	store := redis.ProvideStore(context, tenantConfiguration, timeProvider)
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	loginidProvider := loginid.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider)
	anonymousProvider := anonymous.ProvideProvider(sqlBuilder, sqlExecutor)
	providerProvider := &provider.Provider{
		LoginID:   loginidProvider,
		OAuth:     oauthProvider,
		Anonymous: anonymousProvider,
	}
	passwordhistoryStore := pq.ProvidePasswordHistoryStore(timeProvider, sqlBuilder, sqlExecutor)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, passwordhistoryStore)
	passwordProvider := password.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, factory, passwordhistoryStore, passwordChecker, tenantConfiguration)
	totpProvider := totp.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	urlprefixProvider := urlprefix.NewProvider(r)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	oobProvider := oob.ProvideProvider(tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider, engine, urlprefixProvider, queue)
	bearertokenProvider := bearertoken.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration)
	recoverycodeProvider := recoverycode.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration)
	provider3 := &provider2.Provider{
		Password:     passwordProvider,
		TOTP:         totpProvider,
		OOBOTP:       oobProvider,
		BearerToken:  bearertokenProvider,
		RecoveryCode: recoverycodeProvider,
	}
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(timeProvider, sqlBuilder, sqlExecutor)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, timeProvider, authinfoStore, userprofileStore, loginidProvider, factory)
	userProvider := interaction.ProvideUserProvider(authinfoStore, userprofileStore, timeProvider, hookProvider, urlprefixProvider, queue, tenantConfiguration)
	interactionProvider := interaction.ProvideProvider(store, timeProvider, factory, providerProvider, provider3, userProvider, oobProvider, tenantConfiguration, hookProvider)
	authorizationStore := &pq3.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis2.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider)
	eventStore := redis3.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionStore := redis4.ProvideStore(context, tenantConfiguration, timeProvider, factory)
	authAccessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, authAccessEventProvider, tenantConfiguration)
	challengeProvider := challenge.ProvideProvider(context, timeProvider, tenantConfiguration)
	anonymousFlow := &flows.AnonymousFlow{
		Interactions: interactionProvider,
		Anonymous:    anonymousProvider,
		Challenges:   challengeProvider,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, urlprefixProvider, authinfoStore, userprofileStore, timeProvider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler2.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, accessEventProvider, sessionProvider, anonymousFlow, idTokenIssuer, tokenGenerator, timeProvider)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	userController := flows.ProvideUserController(authinfoStore, userprofileStore, tokenHandler, cookieConfiguration, sessionProvider, hookProvider, timeProvider, tenantConfiguration)
	authAPIFlow := &flows.AuthAPIFlow{
		Interactions:   interactionProvider,
		UserController: userController,
	}
	httpHandler := provideAddLoginIDHandler(validator, requireAuthz, txContext, authAPIFlow)
	return httpHandler
}

var (
	_wireTokenGeneratorValue = handler2.TokenGenerator(oauth2.GenerateToken)
)

func newRemoveLoginIDHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	validator := auth.ProvideValidator(m)
	context := auth.ProvideContext(r)
	requestID := auth.ProvideLoggingRequestID(r)
	tenantConfiguration := auth.ProvideTenantConfig(context, m)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	requireAuthz := handler.NewRequireAuthzFactory(factory)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	timeProvider := time.NewProvider()
	store := redis.ProvideStore(context, tenantConfiguration, timeProvider)
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	loginidProvider := loginid.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider)
	anonymousProvider := anonymous.ProvideProvider(sqlBuilder, sqlExecutor)
	providerProvider := &provider.Provider{
		LoginID:   loginidProvider,
		OAuth:     oauthProvider,
		Anonymous: anonymousProvider,
	}
	passwordhistoryStore := pq.ProvidePasswordHistoryStore(timeProvider, sqlBuilder, sqlExecutor)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, passwordhistoryStore)
	passwordProvider := password.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, factory, passwordhistoryStore, passwordChecker, tenantConfiguration)
	totpProvider := totp.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	urlprefixProvider := urlprefix.NewProvider(r)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	oobProvider := oob.ProvideProvider(tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider, engine, urlprefixProvider, queue)
	bearertokenProvider := bearertoken.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration)
	recoverycodeProvider := recoverycode.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration)
	provider3 := &provider2.Provider{
		Password:     passwordProvider,
		TOTP:         totpProvider,
		OOBOTP:       oobProvider,
		BearerToken:  bearertokenProvider,
		RecoveryCode: recoverycodeProvider,
	}
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(timeProvider, sqlBuilder, sqlExecutor)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, timeProvider, authinfoStore, userprofileStore, loginidProvider, factory)
	userProvider := interaction.ProvideUserProvider(authinfoStore, userprofileStore, timeProvider, hookProvider, urlprefixProvider, queue, tenantConfiguration)
	interactionProvider := interaction.ProvideProvider(store, timeProvider, factory, providerProvider, provider3, userProvider, oobProvider, tenantConfiguration, hookProvider)
	authorizationStore := &pq3.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis2.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider)
	eventStore := redis3.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionStore := redis4.ProvideStore(context, tenantConfiguration, timeProvider, factory)
	authAccessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, authAccessEventProvider, tenantConfiguration)
	challengeProvider := challenge.ProvideProvider(context, timeProvider, tenantConfiguration)
	anonymousFlow := &flows.AnonymousFlow{
		Interactions: interactionProvider,
		Anonymous:    anonymousProvider,
		Challenges:   challengeProvider,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, urlprefixProvider, authinfoStore, userprofileStore, timeProvider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler2.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, accessEventProvider, sessionProvider, anonymousFlow, idTokenIssuer, tokenGenerator, timeProvider)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	userController := flows.ProvideUserController(authinfoStore, userprofileStore, tokenHandler, cookieConfiguration, sessionProvider, hookProvider, timeProvider, tenantConfiguration)
	authAPIFlow := &flows.AuthAPIFlow{
		Interactions:   interactionProvider,
		UserController: userController,
	}
	httpHandler := provideRemoveLoginIDHandler(validator, requireAuthz, txContext, authAPIFlow)
	return httpHandler
}

func newUpdateLoginIDHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	validator := auth.ProvideValidator(m)
	context := auth.ProvideContext(r)
	requestID := auth.ProvideLoggingRequestID(r)
	tenantConfiguration := auth.ProvideTenantConfig(context, m)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	requireAuthz := handler.NewRequireAuthzFactory(factory)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	timeProvider := time.NewProvider()
	store := redis.ProvideStore(context, tenantConfiguration, timeProvider)
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	loginidProvider := loginid.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider)
	anonymousProvider := anonymous.ProvideProvider(sqlBuilder, sqlExecutor)
	providerProvider := &provider.Provider{
		LoginID:   loginidProvider,
		OAuth:     oauthProvider,
		Anonymous: anonymousProvider,
	}
	passwordhistoryStore := pq.ProvidePasswordHistoryStore(timeProvider, sqlBuilder, sqlExecutor)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, passwordhistoryStore)
	passwordProvider := password.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, factory, passwordhistoryStore, passwordChecker, tenantConfiguration)
	totpProvider := totp.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	urlprefixProvider := urlprefix.NewProvider(r)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	oobProvider := oob.ProvideProvider(tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider, engine, urlprefixProvider, queue)
	bearertokenProvider := bearertoken.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration)
	recoverycodeProvider := recoverycode.ProvideProvider(sqlBuilder, sqlExecutor, timeProvider, tenantConfiguration)
	provider3 := &provider2.Provider{
		Password:     passwordProvider,
		TOTP:         totpProvider,
		OOBOTP:       oobProvider,
		BearerToken:  bearertokenProvider,
		RecoveryCode: recoverycodeProvider,
	}
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(timeProvider, sqlBuilder, sqlExecutor)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, timeProvider, authinfoStore, userprofileStore, loginidProvider, factory)
	userProvider := interaction.ProvideUserProvider(authinfoStore, userprofileStore, timeProvider, hookProvider, urlprefixProvider, queue, tenantConfiguration)
	interactionProvider := interaction.ProvideProvider(store, timeProvider, factory, providerProvider, provider3, userProvider, oobProvider, tenantConfiguration, hookProvider)
	authorizationStore := &pq3.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis2.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, timeProvider)
	eventStore := redis3.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionStore := redis4.ProvideStore(context, tenantConfiguration, timeProvider, factory)
	authAccessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, authAccessEventProvider, tenantConfiguration)
	challengeProvider := challenge.ProvideProvider(context, timeProvider, tenantConfiguration)
	anonymousFlow := &flows.AnonymousFlow{
		Interactions: interactionProvider,
		Anonymous:    anonymousProvider,
		Challenges:   challengeProvider,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, urlprefixProvider, authinfoStore, userprofileStore, timeProvider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler2.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, accessEventProvider, sessionProvider, anonymousFlow, idTokenIssuer, tokenGenerator, timeProvider)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	userController := flows.ProvideUserController(authinfoStore, userprofileStore, tokenHandler, cookieConfiguration, sessionProvider, hookProvider, timeProvider, tenantConfiguration)
	authAPIFlow := &flows.AuthAPIFlow{
		Interactions:   interactionProvider,
		UserController: userController,
	}
	httpHandler := provideUpdateLoginIDHandler(validator, requireAuthz, txContext, authAPIFlow)
	return httpHandler
}

// wire.go:

func provideAddLoginIDHandler(
	v *validation.Validator,
	requireAuthz handler.RequireAuthz,
	tx db.TxContext,
	f AddLoginIDInteractionFlow,
) http.Handler {
	h := &AddLoginIDHandler{
		Validator:    v,
		TxContext:    tx,
		Interactions: f,
	}
	return requireAuthz(h, h)
}

func provideRemoveLoginIDHandler(
	v *validation.Validator,
	requireAuthz handler.RequireAuthz,
	tx db.TxContext,
	f RemoveLoginIDInteractionFlow,
) http.Handler {
	h := &RemoveLoginIDHandler{
		Validator:    v,
		TxContext:    tx,
		Interactions: f,
	}
	return requireAuthz(h, h)
}

func provideUpdateLoginIDHandler(
	v *validation.Validator,
	requireAuthz handler.RequireAuthz,
	tx db.TxContext,
	f UpdateLoginIDInteractionFlow,
) http.Handler {
	h := &UpdateLoginIDHandler{
		Validator:    v,
		TxContext:    tx,
		Interactions: f,
	}
	return requireAuthz(h, h)
}
