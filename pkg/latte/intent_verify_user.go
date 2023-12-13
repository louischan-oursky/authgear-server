package latte

import (
	"context"

	"github.com/authgear/authgear-server/pkg/api/apierrors"
	"github.com/authgear/authgear-server/pkg/api/event"
	"github.com/authgear/authgear-server/pkg/api/event/nonblocking"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
	"github.com/authgear/authgear-server/pkg/util/accesscontrol"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

func init() {
	workflow.RegisterPublicIntent(&IntentVerifyUser{})
}

var IntentVerifyUserSchema = validation.NewSimpleSchema(`
	{
		"type": "object",
		"additionalProperties": false
	}
`)

type IntentVerifyUser struct {
}

var _ workflow.AfterCommit = &IntentVerifyUser{}

func (*IntentVerifyUser) Kind() string {
	return "latte.IntentVerifyUser"
}

func (*IntentVerifyUser) JSONSchema() *validation.SimpleSchema {
	return IntentVerifyUserSchema
}

func (*IntentVerifyUser) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	if len(workflows.Nearest.Nodes) == 0 {
		return nil, nil
	}
	return nil, workflow.ErrEOF
}

func (*IntentVerifyUser) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	userID := session.GetUserID(ctx)
	if userID == nil {
		return nil, apierrors.NewUnauthorized("authentication required")
	}

	return workflow.NewSubWorkflow(&IntentFindVerifyIdentity{
		UserID: *userID,
	}), nil
}

func (*IntentVerifyUser) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return
}

func (*IntentVerifyUser) AfterCommit(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) error {
	verifyIdentity, workflow := workflow.MustFindSubWorkflow[*IntentFindVerifyIdentity](workflows.Nearest)
	verified, ok := verifyIdentity.VerifiedIdentity(workflow)
	if !ok || verified.NewVerifiedClaim == nil {
		// No actual verification is done; skipping event
		return nil
	}

	var payload event.NonBlockingPayload
	err := deps.Database.ReadOnly(func() error {
		iden, err := deps.Identities.Get(verified.IdentityID)
		if err != nil {
			return err
		}

		userModel, err := deps.Users.Get(iden.UserID, accesscontrol.RoleGreatest)
		if err != nil {
			return err
		}

		payload, ok = nonblocking.NewIdentityVerifiedEventPayloadUserModel(
			*userModel,
			iden.ToModel(),
			string(verified.NewVerifiedClaim.Name),
			false,
		)

		return nil
	})
	if err != nil {
		return err
	}

	if payload != nil {
		err := deps.NonblockingEvents.DispatchEvent(payload)
		if err != nil {
			return err
		}
	}

	return nil
}

func (i *IntentVerifyUser) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return nil, nil
}
