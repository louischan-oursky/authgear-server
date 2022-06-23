package service

import (
	"time"

	"github.com/authgear/authgear-server/pkg/api/apierrors"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/globaldb"
	"github.com/authgear/authgear-server/pkg/portal/libstripe"
	"github.com/authgear/authgear-server/pkg/portal/model"
	"github.com/authgear/authgear-server/pkg/util/uuid"
)

var ErrSubscriptionCheckoutNotFound = apierrors.NotFound.WithReason("ErrSubscriptionCheckoutNotFound").
	New("subscription checkout not found")

type SubscriptionService struct {
	SQLBuilder  *globaldb.SQLBuilder
	SQLExecutor *globaldb.SQLExecutor
}

func (s *SubscriptionService) CreateSubscription(appID string, stripeSubscriptionID string, stripeCustomerID string) (*model.Subscription, error) {
	subscription := &model.Subscription{
		ID:                   uuid.New(),
		AppID:                appID,
		StripeCustomerID:     stripeCustomerID,
		StripeSubscriptionID: stripeSubscriptionID,
	}

	if err := s.createSubscription(subscription); err != nil {
		return nil, err
	}

	return subscription, nil
}

func (s *SubscriptionService) CreateSubscriptionCheckout(checkoutSession *libstripe.CheckoutSession) (*model.SubscriptionCheckout, error) {
	cs := &model.SubscriptionCheckout{
		ID:                      uuid.New(),
		StripeCheckoutSessionID: checkoutSession.StripeCheckoutSessionID,
		AppID:                   checkoutSession.AppID,
		Status:                  model.SubscriptionCheckoutStatusOpen,
		ExpireAt:                time.Unix(checkoutSession.ExpiresAt, 0).UTC(),
	}
	if err := s.createSubscriptionCheckout(cs); err != nil {
		return nil, err
	}
	return cs, nil
}

// UpdateSubscriptionCheckoutStatus updates subscription checkout status and customer id
// It returns ErrSubscriptionCheckoutNotFound when the checkout is not found
// or the checkout status is already subscribed
func (s *SubscriptionService) UpdateSubscriptionCheckoutStatusAndCustomerID(appID string, stripCheckoutSessionID string, status model.SubscriptionCheckoutStatus, customerID string) error {
	q := s.SQLBuilder.
		Update(s.SQLBuilder.TableName("_portal_subscription_checkout")).
		Set("status", status).
		Set("stripe_customer_id", customerID).
		Where("stripe_checkout_session_id = ?", stripCheckoutSessionID).
		Where("app_id = ?", appID).
		// Only allow updating status if it is not subscribed
		Where("status != 'subscribed'")

	result, err := s.SQLExecutor.ExecWith(q)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrSubscriptionCheckoutNotFound
	}

	return nil
}

func (s *SubscriptionService) createSubscription(sub *model.Subscription) error {
	_, err := s.SQLExecutor.ExecWith(s.SQLBuilder.
		Insert(s.SQLBuilder.TableName("_portal_subscription")).
		Columns(
			"id",
			"app_id",
			"stripe_customer_id",
			"stripe_subscription_id",
		).
		Values(
			sub.ID,
			sub.AppID,
			sub.StripeCustomerID,
			sub.StripeSubscriptionID,
		),
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *SubscriptionService) createSubscriptionCheckout(sc *model.SubscriptionCheckout) error {
	_, err := s.SQLExecutor.ExecWith(s.SQLBuilder.
		Insert(s.SQLBuilder.TableName("_portal_subscription_checkout")).
		Columns(
			"id",
			"app_id",
			"stripe_checkout_session_id",
			"stripe_customer_id",
			"status",
			"expire_at",
		).
		Values(
			sc.ID,
			sc.AppID,
			sc.StripeCheckoutSessionID,
			sc.StripeCustomerID,
			sc.Status,
			sc.ExpireAt,
		),
	)
	if err != nil {
		return err
	}

	return nil
}
