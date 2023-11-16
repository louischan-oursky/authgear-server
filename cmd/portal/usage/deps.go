package usage

import (
	"github.com/google/wire"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/auditdb"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/globaldb"
	"github.com/authgear/authgear-server/pkg/lib/infra/redis/analyticredis"
	"github.com/authgear/authgear-server/pkg/lib/meter"
	"github.com/authgear/authgear-server/pkg/lib/usage"
	"github.com/authgear/authgear-server/pkg/util/cobrasentry"
)

func NewGlobalDatabaseCredentials(dbCredentials *config.DatabaseCredentials) *config.GlobalDatabaseCredentialsEnvironmentConfig {
	return &config.GlobalDatabaseCredentialsEnvironmentConfig{
		DatabaseURL:    dbCredentials.DatabaseURL,
		DatabaseSchema: dbCredentials.DatabaseSchema,
	}
}

func NewNoopTracer() trace.Tracer {
	return noop.NewTracerProvider().Tracer("noop-tracer")
}

var DependencySet = wire.NewSet(
	NewNoopTracer,
	cobrasentry.NewLoggerFactory,
	config.NewDefaultDatabaseEnvironmentConfig,
	NewGlobalDatabaseCredentials,
	config.NewDefaultRedisEnvironmentConfig,
	globaldb.DependencySet,
	auditdb.DependencySet,
	auditdb.NewReadHandle,
	analyticredis.NewHandle,
	meter.DependencySet,

	usage.DependencySet,
	wire.Bind(new(usage.ReadCounterStore), new(*meter.ReadStoreRedis)),
	wire.Bind(new(usage.MeterAuditDBStore), new(*meter.AuditDBReadStore)),
)
