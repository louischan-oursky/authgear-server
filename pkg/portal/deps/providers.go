package deps

import (
	"net/http"

	getsentry "github.com/getsentry/sentry-go"

	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/config/configsource"
	libresource "github.com/authgear/authgear-server/pkg/lib/resource"
	portalconfig "github.com/authgear/authgear-server/pkg/portal/config"
	"github.com/authgear/authgear-server/pkg/portal/db"
	portalresource "github.com/authgear/authgear-server/pkg/portal/resource"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/log"
	"github.com/authgear/authgear-server/pkg/util/resource"
	"github.com/authgear/authgear-server/pkg/util/sentry"
)

type RootProvider struct {
	EnvironmentConfig  *config.EnvironmentConfig
	ConfigSourceConfig *configsource.Config
	AuthgearConfig     *portalconfig.AuthgearConfig
	AdminAPIConfig     *portalconfig.AdminAPIConfig
	AppConfig          *portalconfig.AppConfig
	DatabaseConfig     *portalconfig.DatabaseConfig
	SMTPConfig         *portalconfig.SMTPConfig
	MailConfig         *portalconfig.MailConfig
	LoggerFactory      *log.Factory
	SentryHub          *getsentry.Hub

	Database               *db.Pool
	ConfigSourceController *configsource.Controller
	Resources              *resource.Manager
	AppBaseResources       *resource.Manager

	SecretKeyAllowlist portalconfig.SecretKeyAllowlist
}

func NewRootProvider(
	cfg *config.EnvironmentConfig,
	builtinResourceDirectory string,
	customResourceDirectory string,
	appBuiltinResourceDirectory string,
	appCustomResourceDirectory string,
	configSourceConfig *configsource.Config,
	authgearConfig *portalconfig.AuthgearConfig,
	adminAPIConfig *portalconfig.AdminAPIConfig,
	appConfig *portalconfig.AppConfig,
	dbConfig *portalconfig.DatabaseConfig,
	smtpConfig *portalconfig.SMTPConfig,
	mailConfig *portalconfig.MailConfig,
	secretKeyAllowlist portalconfig.SecretKeyAllowlist,
) (*RootProvider, error) {
	logLevel, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		return nil, err
	}

	sentryHub, err := sentry.NewHub(string(cfg.SentryDSN))
	if err != nil {
		return nil, err
	}

	loggerFactory := log.NewFactory(
		logLevel,
		log.NewDefaultMaskLogHook(),
		sentry.NewLogHookFromHub(sentryHub),
	)

	return &RootProvider{
		EnvironmentConfig:  cfg,
		ConfigSourceConfig: configSourceConfig,
		AuthgearConfig:     authgearConfig,
		AdminAPIConfig:     adminAPIConfig,
		AppConfig:          appConfig,
		DatabaseConfig:     dbConfig,
		SMTPConfig:         smtpConfig,
		MailConfig:         mailConfig,
		LoggerFactory:      loggerFactory,
		SentryHub:          sentryHub,
		Database:           db.NewPool(dbConfig),
		Resources: libresource.NewResourceManager(
			portalresource.PortalRegistry,
			builtinResourceDirectory,
			customResourceDirectory,
		),
		AppBaseResources: libresource.NewResourceManager(
			patchDefaultRegistry(resource.DefaultRegistry, secretKeyAllowlist),
			appBuiltinResourceDirectory,
			appCustomResourceDirectory,
		),
		SecretKeyAllowlist: secretKeyAllowlist,
	}, nil
}

func patchDefaultRegistry(registry *resource.Registry, secretKeyAllowlist portalconfig.SecretKeyAllowlist) *resource.Registry {
	newRegistry := &resource.Registry{}

	newSecretConfigDescriptor := portalresource.SecretConfigResourceType{
		SecretKeyAllowlist: secretKeyAllowlist,
	}
	for _, d := range registry.Descriptors {
		if d == configsource.SecretConfig {
			// Skip this.
		} else {
			newRegistry.Register(d)
		}
	}

	newRegistry.Register(newSecretConfigDescriptor)
	return newRegistry
}

type RequestProvider struct {
	RootProvider *RootProvider
	Request      *http.Request
}

func (p *RootProvider) Middleware(f func(*RequestProvider) httproute.Middleware) httproute.Middleware {
	return httproute.MiddlewareFunc(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestProvider := &RequestProvider{
				RootProvider: p,
				Request:      r,
			}
			m := f(requestProvider)
			h := m.Handle(next)
			h.ServeHTTP(w, r)
		})
	})
}

func (p *RootProvider) Handler(f func(*RequestProvider) http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestProvider := &RequestProvider{
			RootProvider: p,
			Request:      r,
		}
		h := f(requestProvider)
		h.ServeHTTP(w, r)
	})
}
