// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package background

import (
	"context"
	"github.com/authgear/authgear-server/pkg/lib/config/configsource"
	"github.com/authgear/authgear-server/pkg/lib/deps"
	"github.com/authgear/authgear-server/pkg/lib/feature/accountdeletion"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/globaldb"
	"github.com/authgear/authgear-server/pkg/util/backgroundjob"
	"github.com/authgear/authgear-server/pkg/util/clock"
)

// Injectors from wire.go:

func newConfigSourceController(p *deps.BackgroundProvider, c context.Context) *configsource.Controller {
	config := p.ConfigSourceConfig
	factory := p.LoggerFactory
	localFSLogger := configsource.NewLocalFSLogger(factory)
	manager := p.BaseResources
	localFS := &configsource.LocalFS{
		Logger:        localFSLogger,
		BaseResources: manager,
		Config:        config,
	}
	databaseLogger := configsource.NewDatabaseLogger(factory)
	environmentConfig := p.EnvironmentConfig
	trustProxy := environmentConfig.TrustProxy
	clock := _wireSystemClockValue
	databaseEnvironmentConfig := &environmentConfig.Database
	sqlBuilder := globaldb.NewSQLBuilder(databaseEnvironmentConfig)
	pool := p.DatabasePool
	handle := globaldb.NewHandle(c, pool, databaseEnvironmentConfig, factory)
	sqlExecutor := globaldb.NewSQLExecutor(c, handle)
	store := &configsource.Store{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	database := &configsource.Database{
		Logger:         databaseLogger,
		BaseResources:  manager,
		TrustProxy:     trustProxy,
		Config:         config,
		Clock:          clock,
		Store:          store,
		Database:       handle,
		DatabaseConfig: databaseEnvironmentConfig,
	}
	controller := configsource.NewController(config, localFS, database)
	return controller
}

var (
	_wireSystemClockValue = clock.NewSystemClock()
)

func newAccountDeletionRunner(p *deps.BackgroundProvider, c context.Context) *backgroundjob.Runner {
	factory := p.LoggerFactory
	pool := p.DatabasePool
	environmentConfig := p.EnvironmentConfig
	databaseEnvironmentConfig := &environmentConfig.Database
	handle := globaldb.NewHandle(c, pool, databaseEnvironmentConfig, factory)
	sqlBuilder := globaldb.NewSQLBuilder(databaseEnvironmentConfig)
	sqlExecutor := globaldb.NewSQLExecutor(c, handle)
	clockClock := _wireSystemClockValue
	store := &accountdeletion.Store{
		Handle:      handle,
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
		Clock:       clockClock,
	}
	runnable := &accountdeletion.Runnable{
		Store: store,
	}
	runner := accountdeletion.NewRunner(factory, runnable)
	return runner
}
