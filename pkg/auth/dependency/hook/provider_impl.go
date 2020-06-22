package hook

import (
	"context"
	"fmt"
	"time"

	"github.com/skygeario/skygear-server/pkg/auth/dependency/auth"
	"github.com/skygeario/skygear-server/pkg/auth/event"
	"github.com/skygeario/skygear-server/pkg/auth/model"
	"github.com/skygeario/skygear-server/pkg/clock"
	"github.com/skygeario/skygear-server/pkg/core/authn"
	"github.com/skygeario/skygear-server/pkg/core/errors"
	"github.com/skygeario/skygear-server/pkg/core/skyerr"
	"github.com/skygeario/skygear-server/pkg/db"
	"github.com/skygeario/skygear-server/pkg/log"
)

//go:generate mockgen -source=provider_impl.go -destination=provider_impl_mock_test.go -package hook

type UserProvider interface {
	Get(id string) (*model.User, error)
	UpdateMetadata(user *model.User, metadata map[string]interface{}) error
}

type providerImpl struct {
	Store                   Store
	Context                 context.Context
	DBContext               db.Context
	Clock                   clock.Clock
	Users                   UserProvider
	Deliverer               Deliverer
	PersistentEventPayloads []event.Payload
	Logger                  *log.Logger

	txHooked bool
}

func NewProvider(
	ctx context.Context,
	store Store,
	dbContext db.Context,
	clock clock.Clock,
	users UserProvider,
	deliverer Deliverer,
	loggerFactory logging.Factory,
) Provider {
	return &providerImpl{
		Context:   ctx,
		Store:     store,
		DBContext: dbContext,
		Clock:     clock,
		Users:     users,
		Deliverer: deliverer,
		Logger:    loggerFactory.NewLogger("hook"),
	}
}

func (provider *providerImpl) DispatchEvent(payload event.Payload, user *model.User) (err error) {
	var seq int64
	switch typedPayload := payload.(type) {
	case event.OperationPayload:
		if provider.Deliverer.WillDeliver(typedPayload.BeforeEventType()) {
			seq, err = provider.Store.NextSequenceNumber()
			if err != nil {
				err = errors.HandledWithMessage(err, "failed to dispatch event")
				return
			}
			event := event.NewBeforeEvent(seq, typedPayload, provider.makeContext())
			err = provider.Deliverer.DeliverBeforeEvent(event, user)
			if err != nil {
				if !skyerr.IsKind(err, WebHookDisallowed) {
					err = errors.HandledWithMessage(err, "failed to dispatch event")
				}
				return
			}

			// update payload since it may have been updated by mutations
			payload = event.Payload
		}

		provider.PersistentEventPayloads = append(provider.PersistentEventPayloads, payload)

	case event.NotificationPayload:
		provider.PersistentEventPayloads = append(provider.PersistentEventPayloads, payload)
		err = nil

	default:
		panic(fmt.Sprintf("hook: invalid event payload: %T", payload))
	}

	if !provider.txHooked {
		provider.DBContext.UseHook(provider)
		provider.txHooked = true
	}
	return
}

func (provider *providerImpl) WillCommitTx() error {
	err := provider.dispatchSyncUserEventIfNeeded()
	if err != nil {
		return err
	}

	events := []*event.Event{}
	for _, payload := range provider.PersistentEventPayloads {
		var ev *event.Event

		switch typedPayload := payload.(type) {
		case event.OperationPayload:
			if provider.Deliverer.WillDeliver(typedPayload.AfterEventType()) {
				seq, err := provider.Store.NextSequenceNumber()
				if err != nil {
					err = errors.HandledWithMessage(err, "failed to persist event")
					return err
				}
				ev = event.NewAfterEvent(seq, typedPayload, provider.makeContext())
			}

		case event.NotificationPayload:
			if provider.Deliverer.WillDeliver(typedPayload.EventType()) {
				seq, err := provider.Store.NextSequenceNumber()
				if err != nil {
					err = errors.HandledWithMessage(err, "failed to persist event")
					return err
				}
				ev = event.NewEvent(seq, typedPayload, provider.makeContext())
			}

		default:
			panic(fmt.Sprintf("hook: invalid event payload: %T", payload))
		}

		if ev == nil {
			continue
		}
		events = append(events, ev)
	}

	err = provider.Store.AddEvents(events)
	if err != nil {
		err = errors.HandledWithMessage(err, "failed to persist event")
		return err
	}
	provider.PersistentEventPayloads = nil

	return nil
}

func (provider *providerImpl) DidCommitTx() {
	// TODO(webhook): deliver persisted events
	events, _ := provider.Store.GetEventsForDelivery()
	for _, event := range events {
		err := provider.Deliverer.DeliverNonBeforeEvent(event, 60*time.Second)
		if err != nil {
			provider.Logger.WithError(err).Debug("Failed to dispatch event")
		}
	}
}

func (provider *providerImpl) dispatchSyncUserEventIfNeeded() error {
	userIDToSync := []string{}

	for _, payload := range provider.PersistentEventPayloads {
		if _, isOperation := payload.(event.OperationPayload); !isOperation {
			continue
		}
		if userAwarePayload, ok := payload.(event.UserAwarePayload); ok {
			userIDToSync = append(userIDToSync, userAwarePayload.UserID())
		}
	}

	for _, userID := range userIDToSync {
		user, err := provider.Users.Get(userID)
		if err != nil {
			return err
		}

		payload := event.UserSyncEvent{User: *user}
		err = provider.DispatchEvent(payload, user)
		if err != nil {
			return err
		}
	}

	return nil
}

func (provider *providerImpl) makeContext() event.Context {
	var userID *string
	var session *model.Session

	user := authn.GetUser(provider.Context)
	sess := authn.GetSession(provider.Context)
	if user == nil {
		userID = nil
		session = nil
	} else {
		userID = &user.ID
		session = sess.(auth.AuthSession).ToAPIModel()
	}

	return event.Context{
		Timestamp: provider.Clock.NowUTC().Unix(),
		UserID:    userID,
		Session:   session,
	}
}
