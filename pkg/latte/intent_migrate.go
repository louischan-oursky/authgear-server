package latte

import (
	"context"
	"fmt"

	"github.com/authgear/authgear-server/pkg/api/event/blocking"
	"github.com/authgear/authgear-server/pkg/api/event/nonblocking"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
	"github.com/authgear/authgear-server/pkg/util/accesscontrol"
	"github.com/authgear/authgear-server/pkg/util/uuid"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

func init() {
	workflow.RegisterPublicIntent(&IntentMigrate{})
}

var IntentMigrateSchema = validation.NewSimpleSchema(`
	{
		"type": "object",
		"additionalProperties": false
	}
`)

type IntentMigrate struct{}

func (*IntentMigrate) Kind() string {
	return "latte.IntentMigrate"
}

func (*IntentMigrate) JSONSchema() *validation.SimpleSchema {
	return IntentMigrateSchema
}

func (*IntentMigrate) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	switch len(workflows.Nearest.Nodes) {
	case 0:
		// Generate a new user ID.
		return nil, nil
	case 1:
		// Migrate from the migration token.
		return nil, nil
	case 2:
		// Create a email login ID.
		// We assume the project is set to skip verify email on sign up.
		return nil, nil
	case 3:
		// Create a primary password.
		return nil, nil
	case 4:
		// Create a session, if needed.
		return nil, nil
	default:
		return nil, workflow.ErrEOF
	}
}

func (i *IntentMigrate) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	// Check the migration token
	switch len(workflows.Nearest.Nodes) {
	case 0:
		userID := uuid.New()
		u := deps.Accounts.NewUser(userID)
		return workflow.NewNodeSimple(&NodeDoCreateUser{
			User: u,
		}), nil
	case 1:
		return workflow.NewSubWorkflow(&IntentMigrateAccount{
			UseID: i.userID(workflows.Nearest),
		}), nil
	case 2:
		return workflow.NewSubWorkflow(&IntentCreateLoginID{
			// LoginID key and LoginID type are fixed here.
			UserID:      i.userID(workflows.Nearest),
			LoginIDType: model.LoginIDKeyTypeEmail,
			LoginIDKey:  string(model.LoginIDKeyTypeEmail),
		}), nil
	case 3:
		// The type, kind is fixed here.
		return workflow.NewSubWorkflow(&IntentCreatePassword{
			UserID:                 i.userID(workflows.Nearest),
			AuthenticatorKind:      authenticator.KindPrimary,
			AuthenticatorIsDefault: false,
		}), nil
	case 4:
		mode := EnsureSessionModeCreate
		if workflow.GetSuppressIDPSessionCookie(ctx) {
			mode = EnsureSessionModeNoop
		}
		return workflow.NewSubWorkflow(&IntentEnsureSession{
			UserID:       i.userID(workflows.Nearest),
			CreateReason: session.CreateReasonSignup,
			// AMR is NOT populated because
			// 1. Strictly speaking this is NOT an authentication. It is a sign up.
			// 2. 3 authenticators were created. Should we report all 3?
			AMR:  nil,
			Mode: mode,
		}), nil
	}

	return nil, workflow.ErrIncompatibleInput
}

// nolint:gocognit
func (i *IntentMigrate) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return []workflow.Effect{
		workflow.OnCommitEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			// Apply ratelimit on sign up.
			spec := SignupPerIPRateLimitBucketSpec(deps.Config.Authentication, false, string(deps.RemoteIP))
			err := deps.RateLimiter.Allow(spec)
			if err != nil {
				return err
			}
			return nil
		}),
		workflow.OnCommitEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			// Dispatch user.pre_create and apply mutation
			var identities []*identity.Info
			identityWorkflows := workflow.FindSubWorkflows[NewIdentityGetter](workflows.Nearest)
			for _, subWorkflow := range identityWorkflows {
				if iden, ok := subWorkflow.Intent.(NewIdentityGetter).GetNewIdentities(subWorkflow); ok {
					identities = append(identities, iden...)
				}
			}

			var identityModels []model.Identity
			for _, i := range identities {
				identityModels = append(identityModels, i.ToModel())
			}

			userID := i.userID(workflows.Nearest)
			isAdminAPI := false

			userModel, err := deps.Users.Get(userID, accesscontrol.RoleGreatest)
			if err != nil {
				return err
			}

			payload := &blocking.UserPreCreateBlockingEventPayload{
				UserModel:  *userModel,
				Identities: identityModels,
				AdminAPI:   isAdminAPI,
			}

			mutations, err := deps.BlockingEvents.DispatchEvent(payload)
			if err != nil {
				return err
			}

			if mutations != nil {
				u, err := deps.Accounts.GetUserByID(userID)
				if err != nil {
					return err
				}

				if mutations.User.StandardAttributes != nil {
					u, err = deps.Accounts.ReplaceStandardAttributes(accesscontrol.RoleGreatest, u, identities, mutations.User.StandardAttributes)
					if err != nil {
						return err
					}
				}

				if mutations.User.CustomAttributes != nil {
					u, err = deps.Accounts.ReplaceCustomAttributes(accesscontrol.RoleGreatest, u, mutations.User.CustomAttributes)
					if err != nil {
						return err
					}
				}

				// FIXME(workflow): new lifecycle for changes by hook.
				err = deps.AccountWriter.UpdateUser(u)
				if err != nil {
					return err
				}
			}

			return nil
		}),
		workflow.OnCommitEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			// Dispatch user.created
			var identities []*identity.Info
			identityWorkflows := workflow.FindSubWorkflows[NewIdentityGetter](workflows.Nearest)
			for _, subWorkflow := range identityWorkflows {
				if iden, ok := subWorkflow.Intent.(NewIdentityGetter).GetNewIdentities(subWorkflow); ok {
					identities = append(identities, iden...)
				}
			}

			var identityModels []model.Identity
			for _, i := range identities {
				identityModels = append(identityModels, i.ToModel())
			}

			userID := i.userID(workflows.Nearest)
			isAdminAPI := false

			userModel, err := deps.Users.Get(userID, accesscontrol.RoleGreatest)
			if err != nil {
				return err
			}

			payload := &nonblocking.UserCreatedEventPayload{
				UserModel:  *userModel,
				Identities: identityModels,
				AdminAPI:   isAdminAPI,
			}

			err = deps.NonBlockingEvents.DispatchEvent(payload)
			if err != nil {
				return err
			}

			return nil
		}),
	}, nil
}

func (*IntentMigrate) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return nil, nil
}

func (i *IntentMigrate) userID(w *workflow.Workflow) string {
	node, ok := workflow.FindSingleNode[*NodeDoCreateUser](w)
	if !ok {
		panic(fmt.Errorf("expected userID"))
	}
	return node.User.ID
}
