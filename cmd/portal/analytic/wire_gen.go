// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package analytic

import (
	"context"
	"github.com/authgear/authgear-server/pkg/lib/analytic"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/auditdb"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/globaldb"
	"github.com/authgear/authgear-server/pkg/lib/infra/redis"
	"github.com/authgear/authgear-server/pkg/lib/infra/redis/analyticredis"
	"github.com/authgear/authgear-server/pkg/lib/meter"
	"github.com/authgear/authgear-server/pkg/util/clock"
	"github.com/authgear/authgear-server/pkg/util/periodical"
)

// Injectors from wire.go:

func NewUserWeeklyReport(ctx context.Context, pool *db.Pool, databaseCredentials *config.DatabaseCredentials) *analytic.UserWeeklyReport {
	globalDatabaseCredentialsEnvironmentConfig := NewGlobalDatabaseCredentials(databaseCredentials)
	databaseEnvironmentConfig := config.NewDefaultDatabaseEnvironmentConfig()
	factory := NewLoggerFactory()
	handle := globaldb.NewHandle(ctx, pool, globalDatabaseCredentialsEnvironmentConfig, databaseEnvironmentConfig, factory)
	sqlBuilder := globaldb.NewSQLBuilder(globalDatabaseCredentialsEnvironmentConfig)
	sqlExecutor := globaldb.NewSQLExecutor(ctx, handle)
	globalDBStore := &analytic.GlobalDBStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	appdbHandle := appdb.NewHandle(ctx, pool, databaseEnvironmentConfig, databaseCredentials, factory)
	appdbSQLBuilder := appdb.NewSQLBuilder(databaseCredentials)
	appdbSQLExecutor := appdb.NewSQLExecutor(ctx, appdbHandle)
	appDBStore := &analytic.AppDBStore{
		SQLBuilder:  appdbSQLBuilder,
		SQLExecutor: appdbSQLExecutor,
	}
	userWeeklyReport := &analytic.UserWeeklyReport{
		GlobalHandle:  handle,
		GlobalDBStore: globalDBStore,
		AppDBHandle:   appdbHandle,
		AppDBStore:    appDBStore,
	}
	return userWeeklyReport
}

func NewProjectHourlyReport(ctx context.Context, pool *db.Pool, databaseCredentials *config.DatabaseCredentials, auditDatabaseCredentials *config.AuditDatabaseCredentials) *analytic.ProjectHourlyReport {
	globalDatabaseCredentialsEnvironmentConfig := NewGlobalDatabaseCredentials(databaseCredentials)
	databaseEnvironmentConfig := config.NewDefaultDatabaseEnvironmentConfig()
	factory := NewLoggerFactory()
	handle := globaldb.NewHandle(ctx, pool, globalDatabaseCredentialsEnvironmentConfig, databaseEnvironmentConfig, factory)
	sqlBuilder := globaldb.NewSQLBuilder(globalDatabaseCredentialsEnvironmentConfig)
	sqlExecutor := globaldb.NewSQLExecutor(ctx, handle)
	globalDBStore := &analytic.GlobalDBStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	appdbHandle := appdb.NewHandle(ctx, pool, databaseEnvironmentConfig, databaseCredentials, factory)
	appdbSQLBuilder := appdb.NewSQLBuilder(databaseCredentials)
	appdbSQLExecutor := appdb.NewSQLExecutor(ctx, appdbHandle)
	appDBStore := &analytic.AppDBStore{
		SQLBuilder:  appdbSQLBuilder,
		SQLExecutor: appdbSQLExecutor,
	}
	projectHourlyReport := &analytic.ProjectHourlyReport{
		GlobalHandle:  handle,
		GlobalDBStore: globalDBStore,
		AppDBHandle:   appdbHandle,
		AppDBStore:    appDBStore,
	}
	return projectHourlyReport
}

func NewProjectWeeklyReport(ctx context.Context, pool *db.Pool, databaseCredentials *config.DatabaseCredentials, auditDatabaseCredentials *config.AuditDatabaseCredentials) *analytic.ProjectWeeklyReport {
	globalDatabaseCredentialsEnvironmentConfig := NewGlobalDatabaseCredentials(databaseCredentials)
	databaseEnvironmentConfig := config.NewDefaultDatabaseEnvironmentConfig()
	factory := NewLoggerFactory()
	handle := globaldb.NewHandle(ctx, pool, globalDatabaseCredentialsEnvironmentConfig, databaseEnvironmentConfig, factory)
	sqlBuilder := globaldb.NewSQLBuilder(globalDatabaseCredentialsEnvironmentConfig)
	sqlExecutor := globaldb.NewSQLExecutor(ctx, handle)
	globalDBStore := &analytic.GlobalDBStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	appdbHandle := appdb.NewHandle(ctx, pool, databaseEnvironmentConfig, databaseCredentials, factory)
	appdbSQLBuilder := appdb.NewSQLBuilder(databaseCredentials)
	appdbSQLExecutor := appdb.NewSQLExecutor(ctx, appdbHandle)
	appDBStore := &analytic.AppDBStore{
		SQLBuilder:  appdbSQLBuilder,
		SQLExecutor: appdbSQLExecutor,
	}
	readHandle := auditdb.NewReadHandle(ctx, pool, databaseEnvironmentConfig, auditDatabaseCredentials, factory)
	auditdbSQLBuilder := auditdb.NewSQLBuilder(auditDatabaseCredentials)
	readSQLExecutor := auditdb.NewReadSQLExecutor(ctx, readHandle)
	auditDBReadStore := &meter.AuditDBReadStore{
		SQLBuilder:  auditdbSQLBuilder,
		SQLExecutor: readSQLExecutor,
	}
	analyticAuditDBReadStore := &analytic.AuditDBReadStore{
		SQLBuilder:  auditdbSQLBuilder,
		SQLExecutor: readSQLExecutor,
	}
	projectWeeklyReport := &analytic.ProjectWeeklyReport{
		GlobalHandle:      handle,
		GlobalDBStore:     globalDBStore,
		AppDBHandle:       appdbHandle,
		AppDBStore:        appDBStore,
		AuditDBHandle:     readHandle,
		MeterAuditDBStore: auditDBReadStore,
		AuditDBStore:      analyticAuditDBReadStore,
	}
	return projectWeeklyReport
}

func NewProjectMonthlyReport(ctx context.Context, pool *db.Pool, databaseCredentials *config.DatabaseCredentials, auditDatabaseCredentials *config.AuditDatabaseCredentials) *analytic.ProjectMonthlyReport {
	globalDatabaseCredentialsEnvironmentConfig := NewGlobalDatabaseCredentials(databaseCredentials)
	databaseEnvironmentConfig := config.NewDefaultDatabaseEnvironmentConfig()
	factory := NewLoggerFactory()
	handle := globaldb.NewHandle(ctx, pool, globalDatabaseCredentialsEnvironmentConfig, databaseEnvironmentConfig, factory)
	sqlBuilder := globaldb.NewSQLBuilder(globalDatabaseCredentialsEnvironmentConfig)
	sqlExecutor := globaldb.NewSQLExecutor(ctx, handle)
	globalDBStore := &analytic.GlobalDBStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	readHandle := auditdb.NewReadHandle(ctx, pool, databaseEnvironmentConfig, auditDatabaseCredentials, factory)
	auditdbSQLBuilder := auditdb.NewSQLBuilder(auditDatabaseCredentials)
	readSQLExecutor := auditdb.NewReadSQLExecutor(ctx, readHandle)
	auditDBReadStore := &analytic.AuditDBReadStore{
		SQLBuilder:  auditdbSQLBuilder,
		SQLExecutor: readSQLExecutor,
	}
	projectMonthlyReport := &analytic.ProjectMonthlyReport{
		GlobalHandle:  handle,
		GlobalDBStore: globalDBStore,
		AuditDBHandle: readHandle,
		AuditDBStore:  auditDBReadStore,
	}
	return projectMonthlyReport
}

func NewCountCollector(ctx context.Context, pool *db.Pool, databaseCredentials *config.DatabaseCredentials, auditDatabaseCredentials *config.AuditDatabaseCredentials, redisPool *redis.Pool, credentials *config.AnalyticRedisCredentials) *analytic.CountCollector {
	globalDatabaseCredentialsEnvironmentConfig := NewGlobalDatabaseCredentials(databaseCredentials)
	databaseEnvironmentConfig := config.NewDefaultDatabaseEnvironmentConfig()
	factory := NewLoggerFactory()
	handle := globaldb.NewHandle(ctx, pool, globalDatabaseCredentialsEnvironmentConfig, databaseEnvironmentConfig, factory)
	sqlBuilder := globaldb.NewSQLBuilder(globalDatabaseCredentialsEnvironmentConfig)
	sqlExecutor := globaldb.NewSQLExecutor(ctx, handle)
	globalDBStore := &analytic.GlobalDBStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	appdbHandle := appdb.NewHandle(ctx, pool, databaseEnvironmentConfig, databaseCredentials, factory)
	appdbSQLBuilder := appdb.NewSQLBuilder(databaseCredentials)
	appdbSQLExecutor := appdb.NewSQLExecutor(ctx, appdbHandle)
	appDBStore := &analytic.AppDBStore{
		SQLBuilder:  appdbSQLBuilder,
		SQLExecutor: appdbSQLExecutor,
	}
	readHandle := auditdb.NewReadHandle(ctx, pool, databaseEnvironmentConfig, auditDatabaseCredentials, factory)
	auditdbSQLBuilder := auditdb.NewSQLBuilder(auditDatabaseCredentials)
	readSQLExecutor := auditdb.NewReadSQLExecutor(ctx, readHandle)
	auditDBReadStore := &analytic.AuditDBReadStore{
		SQLBuilder:  auditdbSQLBuilder,
		SQLExecutor: readSQLExecutor,
	}
	writeHandle := auditdb.NewWriteHandle(ctx, pool, databaseEnvironmentConfig, auditDatabaseCredentials, factory)
	meterAuditDBReadStore := &meter.AuditDBReadStore{
		SQLBuilder:  auditdbSQLBuilder,
		SQLExecutor: readSQLExecutor,
	}
	writeSQLExecutor := auditdb.NewWriteSQLExecutor(ctx, writeHandle)
	auditDBWriteStore := &analytic.AuditDBWriteStore{
		SQLBuilder:  auditdbSQLBuilder,
		SQLExecutor: writeSQLExecutor,
	}
	redisEnvironmentConfig := config.NewDefaultRedisEnvironmentConfig()
	analyticredisHandle := analyticredis.NewHandle(redisPool, redisEnvironmentConfig, credentials, factory)
	readStoreRedis := &meter.ReadStoreRedis{
		Context: ctx,
		Redis:   analyticredisHandle,
	}
	service := &analytic.Service{
		ReadCounter: readStoreRedis,
	}
	countCollector := &analytic.CountCollector{
		GlobalHandle:       handle,
		GlobalDBStore:      globalDBStore,
		AppDBHandle:        appdbHandle,
		AppDBStore:         appDBStore,
		AuditDBReadHandle:  readHandle,
		AuditDBReadStore:   auditDBReadStore,
		AuditDBWriteHandle: writeHandle,
		MeterAuditDBStore:  meterAuditDBReadStore,
		AuditDBWriteStore:  auditDBWriteStore,
		AnalyticService:    service,
	}
	return countCollector
}

func NewPeriodicalArgumentParser() *periodical.ArgumentParser {
	clock := _wireSystemClockValue
	argumentParser := &periodical.ArgumentParser{
		Clock: clock,
	}
	return argumentParser
}

var (
	_wireSystemClockValue = clock.NewSystemClock()
)

func NewPosthogIntegration(ctx context.Context, pool *db.Pool, databaseCredentials *config.DatabaseCredentials, auditDatabaseCredentials *config.AuditDatabaseCredentials, redisPool *redis.Pool, credentials *config.AnalyticRedisCredentials, posthogCredentials *analytic.PosthogCredentials) *analytic.PosthogIntegration {
	posthogIntegration := &analytic.PosthogIntegration{
		PosthogCredentials: posthogCredentials,
	}
	return posthogIntegration
}
