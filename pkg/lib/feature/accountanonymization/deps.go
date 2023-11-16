package accountanonymization

import (
	"context"

	"github.com/google/wire"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/globaldb"
	"github.com/authgear/authgear-server/pkg/util/backgroundjob"
	"github.com/authgear/authgear-server/pkg/util/clock"
	"github.com/authgear/authgear-server/pkg/util/log"
)

func NewRunner(loggerFactory *log.Factory, runnableFactory backgroundjob.RunnableFactory) *backgroundjob.Runner {
	return backgroundjob.NewRunner(
		loggerFactory.New("account-anonymization-runner"),
		runnableFactory,
	)
}

func NewRunnableFactory(
	pool *db.Pool,
	globalDBCredentials *config.GlobalDatabaseCredentialsEnvironmentConfig,
	databaseCfg *config.DatabaseEnvironmentConfig,
	logFactory *log.Factory,
	clock clock.Clock,
	appContextResolver AppContextResolver,
	userServiceFactory UserServiceFactory,
) backgroundjob.RunnableFactory {
	factory := func(ctx context.Context) backgroundjob.Runnable {
		return newRunnable(ctx, pool, globalDBCredentials, databaseCfg, logFactory, clock, appContextResolver, userServiceFactory)
	}
	return factory
}

func NewNoopTracer() trace.Tracer {
	return noop.NewTracerProvider().Tracer("noop-tracer")
}

var DependencySet = wire.NewSet(
	NewRunnableFactory,
	NewRunner,
)

var RunnableDependencySet = wire.NewSet(
	globaldb.DependencySet,
	wire.Struct(new(Store), "*"),
	wire.Struct(new(Runnable), "*"),
	NewRunnableLogger,
	NewNoopTracer,
	wire.Bind(new(backgroundjob.Runnable), new(*Runnable)),
)
