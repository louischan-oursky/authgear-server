// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package task

import (
	"context"
	"github.com/skygeario/skygear-server/pkg/auth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/authenticator/password"
	"github.com/skygeario/skygear-server/pkg/core/async"
	"github.com/skygeario/skygear-server/pkg/core/db"
	"github.com/skygeario/skygear-server/pkg/core/logging"
	"github.com/skygeario/skygear-server/pkg/core/mail"
	"github.com/skygeario/skygear-server/pkg/core/sms"
	"github.com/skygeario/skygear-server/pkg/core/time"
)

// Injectors from wire.go:

func newPwHouseKeeperTask(ctx context.Context, m auth.DependencyMap) async.Task {
	tenantConfiguration := auth.ProvideTenantConfig(ctx, m)
	txContext := db.ProvideTxContext(ctx, tenantConfiguration)
	factory := logging.ProvideLoggerFactory(ctx, tenantConfiguration)
	provider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(ctx, tenantConfiguration)
	historyStoreImpl := password.ProvideHistoryStore(provider, sqlBuilder, sqlExecutor)
	housekeeper := password.ProvideHousekeeper(historyStoreImpl, factory, tenantConfiguration)
	pwHousekeeperTask := &PwHousekeeperTask{
		TxContext:     txContext,
		LoggerFactory: factory,
		PwHousekeeper: housekeeper,
	}
	return pwHousekeeperTask
}

func newSendMessagesTask(ctx context.Context, m auth.DependencyMap) async.Task {
	tenantConfiguration := auth.ProvideTenantConfig(ctx, m)
	sender := mail.ProvideMailSender(ctx, tenantConfiguration)
	client := sms.ProvideSMSClient(ctx, tenantConfiguration)
	factory := logging.ProvideLoggerFactory(ctx, tenantConfiguration)
	sendMessagesTask := &SendMessagesTask{
		EmailSender:   sender,
		SMSClient:     client,
		LoggerFactory: factory,
	}
	return sendMessagesTask
}
