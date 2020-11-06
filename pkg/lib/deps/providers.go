package deps

import (
	"context"
	"net/http"

	getsentry "github.com/getsentry/sentry-go"

	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/config/configsource"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
	"github.com/authgear/authgear-server/pkg/lib/infra/redis"
	"github.com/authgear/authgear-server/pkg/lib/infra/task"
	libresource "github.com/authgear/authgear-server/pkg/lib/resource"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/log"
	"github.com/authgear/authgear-server/pkg/util/resource"
	"github.com/authgear/authgear-server/pkg/util/sentry"
)

type RootProvider struct {
	EnvironmentConfig  *config.EnvironmentConfig
	ConfigSourceConfig *configsource.Config
	LoggerFactory      *log.Factory
	SentryHub          *getsentry.Hub
	DatabasePool       *db.Pool
	RedisPool          *redis.Pool
	TaskQueueFactory   TaskQueueFactory
	BaseResources      *resource.Manager
}

func NewRootProvider(
	cfg *config.EnvironmentConfig,
	configSourceConfig *configsource.Config,
	builtinResourceDirectory string,
	customResourceDirectory string,
	taskQueueFactory TaskQueueFactory,
) (*RootProvider, error) {
	var p RootProvider

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

	dbPool := db.NewPool()
	redisPool := redis.NewPool()

	p = RootProvider{
		EnvironmentConfig:  cfg,
		ConfigSourceConfig: configSourceConfig,
		LoggerFactory:      loggerFactory,
		SentryHub:          sentryHub,
		DatabasePool:       dbPool,
		RedisPool:          redisPool,
		TaskQueueFactory:   taskQueueFactory,
		BaseResources: libresource.NewResourceManager(
			resource.DefaultRegistry,
			builtinResourceDirectory,
			customResourceDirectory,
		),
	}
	return &p, nil
}

func (p *RootProvider) NewAppProvider(ctx context.Context, appCtx *config.AppContext) *AppProvider {
	cfg := appCtx.Config
	loggerFactory := p.LoggerFactory.ReplaceHooks(
		log.NewDefaultMaskLogHook(),
		config.NewSecretMaskLogHook(cfg.SecretConfig),
		sentry.NewLogHookFromContext(ctx),
	)
	loggerFactory.DefaultFields["app"] = cfg.AppConfig.ID
	database := db.NewHandle(
		ctx,
		p.DatabasePool,
		cfg.AppConfig.Database,
		cfg.SecretConfig.LookupData(config.DatabaseCredentialsKey).(*config.DatabaseCredentials),
		loggerFactory,
	)
	redis := redis.NewHandle(
		p.RedisPool,
		cfg.AppConfig.Redis,
		cfg.SecretConfig.LookupData(config.RedisCredentialsKey).(*config.RedisCredentials),
		loggerFactory,
	)

	provider := &AppProvider{
		RootProvider:  p,
		Context:       ctx,
		Config:        cfg,
		LoggerFactory: loggerFactory,
		Database:      database,
		Redis:         redis,
		Resources:     appCtx.Resources,
	}
	provider.TaskQueue = p.TaskQueueFactory(provider)
	return provider
}

func (p *RootProvider) Handler(factory func(*RequestProvider) http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := getRequestProvider(r)
		h := factory(p)
		h.ServeHTTP(w, r)
	})
}

func (p *RootProvider) RootMiddleware(factory func(*RootProvider) httproute.Middleware) httproute.Middleware {
	return factory(p)
}

func (p *RootProvider) Middleware(factory func(*RequestProvider) httproute.Middleware) httproute.Middleware {
	return httproute.MiddlewareFunc(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := getRequestProvider(r)
			m := factory(p)
			h := m.Handle(next)
			h.ServeHTTP(w, r)
		})
	})
}

func (p *RootProvider) Task(factory func(provider *TaskProvider) task.Task) task.Task {
	return TaskFunc(func(ctx context.Context, param task.Param) error {
		p := getTaskProvider(ctx)
		task := factory(p)
		return task.Run(ctx, param)
	})
}

type AppProvider struct {
	*RootProvider

	Context       context.Context
	Config        *config.Config
	LoggerFactory *log.Factory
	Database      *db.Handle
	Redis         *redis.Handle
	TaskQueue     task.Queue
	Resources     *resource.Manager
}

func (p *AppProvider) NewRequestProvider(r *http.Request) *RequestProvider {
	return &RequestProvider{
		AppProvider: p,
		Request:     r,
	}
}

func (p *AppProvider) NewTaskProvider(ctx context.Context) *TaskProvider {
	return &TaskProvider{
		AppProvider: p,
		Context:     ctx,
	}
}

type RequestProvider struct {
	*AppProvider

	Request *http.Request
}

type TaskProvider struct {
	*AppProvider

	Context context.Context
}
