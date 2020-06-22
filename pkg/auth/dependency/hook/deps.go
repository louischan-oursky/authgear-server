package hook

import (
	"context"

	"github.com/google/wire"

	"github.com/skygeario/skygear-server/pkg/auth/dependency/auth"
	"github.com/skygeario/skygear-server/pkg/clock"
	"github.com/skygeario/skygear-server/pkg/core/config"
	"github.com/skygeario/skygear-server/pkg/db"
)

func ProvideHookProvider(
	ctx context.Context,
	sqlb db.SQLBuilder,
	sqle db.SQLExecutor,
	tConfig *config.TenantConfiguration,
	dbContext db.Context,
	timeProvider clock.Clock,
	users UserProvider,
	loginIDProvider LoginIDProvider,
) Provider {
	return NewProvider(
		ctx,
		NewStore(sqlb, sqle),
		dbContext,
		timeProvider,
		users,
		NewDeliverer(
			tConfig,
			timeProvider,
			NewMutator(
				tConfig.AppConfig.UserVerification,
				loginIDProvider,
				users,
			),
		),
		// FIXME: inject logger
		nil,
	)
}

var DependencySet = wire.NewSet(
	ProvideHookProvider,
	wire.Bind(new(auth.HookProvider), new(Provider)),
)
