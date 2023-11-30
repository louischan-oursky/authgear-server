package latte

import (
	"context"
	"errors"
	"fmt"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

func init() {
	workflow.RegisterPrivateIntent(&IntentMigrateLoginID{})
}

var IntentMigrateLoginIDSchema = validation.NewSimpleSchema(`{}`)

type IntentMigrateLoginID struct {
	UserID      string                `json:"user_id"`
	MigrateSpec *identity.MigrateSpec `json:"migrate_spec"`
}

func (*IntentMigrateLoginID) Kind() string {
	return "latte.IntentMigrateLoginID"
}

func (*IntentMigrateLoginID) JSONSchema() *validation.SimpleSchema {
	return IntentMigrateLoginIDSchema
}

func (*IntentMigrateLoginID) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	switch len(workflows.Nearest.Nodes) {
	case 0:
		// Create identity.
		return nil, nil
	case 1:
		// Populate standard attributes.
		return nil, nil
	case 2:
		// Mark identity as verified automatically.
		return nil, nil
	default:
		return nil, workflow.ErrEOF
	}
}

func (i *IntentMigrateLoginID) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	switch len(workflows.Nearest.Nodes) {
	case 0:
		spec := i.MigrateSpec.GetSpec()

		// FIXME(workflow): retrieve dependency elsewhere
		u, err := deps.Accounts.GetUserByID(i.UserID)
		if err != nil {
			return nil, err
		}
		identities, err := deps.Accounts.ListIdentitiesOfUser(i.UserID)
		if err != nil {
			return nil, err
		}
		claims, err := deps.Accounts.ListVerifiedClaimsOfUser(i.UserID)
		if err != nil {
			return nil, err
		}

		changes, err := deps.Accounts.GetNewIdentityChanges(
			spec,
			u,
			identities,
			claims,
		)
		if err != nil {
			return nil, err
		}

		duplicate, err := deps.Accounts.FindDuplicatedIdentity(changes.NewIdentity)
		if err != nil && !errors.Is(err, identity.ErrIdentityAlreadyExists) {
			return nil, err
		}
		// Either err == nil, or err == ErrIdentityAlreadyExists and duplicate is non-nil.
		if err != nil {
			spec := changes.NewIdentity.ToSpec()
			otherSpec := duplicate.ToSpec()
			return nil, identityFillDetails(api.ErrDuplicatedIdentity, &spec, &otherSpec)
		}

		return workflow.NewNodeSimple(&NodeDoCreateIdentity{
			NewIdentityChanges: changes,
		}), nil
	case 1:
		iden := i.identityInfo(workflows.Nearest)
		n, err := NewNodePopulateStandardAttributes(ctx, deps, iden)
		if err != nil {
			return nil, err
		}
		return workflow.NewNodeSimple(n), nil
	case 2:
		// FIXME(workflow): retrieve dependency elsewhere
		claims, err := deps.Accounts.ListVerifiedClaimsOfUser(i.UserID)
		if err != nil {
			return nil, err
		}

		iden := i.identityInfo(workflows.Nearest)
		var verifiedClaim *verification.Claim
		switch iden.LoginID.LoginIDType {
		case model.LoginIDKeyTypeEmail:

			verifiedClaim, _ = deps.Accounts.NewVerifiedClaim(claims, i.UserID, string(model.ClaimEmail), iden.LoginID.LoginID)

		case model.LoginIDKeyTypePhone:
			verifiedClaim, _ = deps.Accounts.NewVerifiedClaim(claims, i.UserID, string(model.ClaimPhoneNumber), iden.LoginID.LoginID)
		}
		return workflow.NewNodeSimple(&NodeVerifiedIdentity{
			IdentityID:       iden.ID,
			NewVerifiedClaim: verifiedClaim,
		}), nil
	}
	return nil, workflow.ErrIncompatibleInput
}

func (i *IntentMigrateLoginID) identityInfo(w *workflow.Workflow) *identity.Info {
	node, ok := workflow.FindSingleNode[*NodeDoCreateIdentity](w)
	if !ok {
		panic(fmt.Errorf("workflow: expected NodeCreateIdentity"))
	}
	return node.NewIdentityChanges.NewIdentity
}

func (*IntentMigrateLoginID) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return nil, nil
}

func (*IntentMigrateLoginID) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return nil, nil
}

func (*IntentMigrateLoginID) GetNewIdentities(w *workflow.Workflow) ([]*identity.Info, bool) {
	node, ok := workflow.FindSingleNode[*NodeDoCreateIdentity](w)
	if !ok {
		return nil, false
	}
	return []*identity.Info{node.NewIdentityChanges.NewIdentity}, true
}
