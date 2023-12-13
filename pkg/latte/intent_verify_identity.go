package latte

import (
	"context"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/otp"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/ratelimit"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

func init() {
	workflow.RegisterPrivateIntent(&IntentVerifyIdentity{})
}

var IntentVerifyIdentitySchema = validation.NewSimpleSchema(`{}`)

type IntentVerifyIdentity struct {
	CaptchaProtectedIntent
	Identity     *identity.Info `json:"identity,omitempty"`
	IsFromSignUp bool           `json:"is_from_signup"`
}

func (*IntentVerifyIdentity) Kind() string {
	return "latte.IntentVerifyIdentity"
}

func (*IntentVerifyIdentity) JSONSchema() *validation.SimpleSchema {
	return IntentVerifyIdentitySchema
}

func (i *IntentVerifyIdentity) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	if i.IsCaptchaProtected {
		switch len(workflows.Nearest.Nodes) {
		case 0:
			return nil, nil
		case 1:
			return nil, nil
		}
	} else {
		switch len(workflows.Nearest.Nodes) {
		case 0:
			return nil, nil
		}
	}
	return nil, workflow.ErrEOF
}

func (i *IntentVerifyIdentity) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	var node *workflow.Node
	err := workflow.WithRunEffects(ctx, deps, workflows, func() error {
		statuses, err := deps.Verification.GetIdentityVerificationStatus(i.Identity)
		if err != nil {
			return err
		}

		var status *verification.ClaimStatus
		if len(statuses) > 0 {
			status = &statuses[0]
		}

		if status == nil || !status.IsVerifiable() {
			return api.ErrClaimNotVerifiable
		}

		if status.Verified || (i.IsFromSignUp && !status.RequiredToVerifyOnCreation) {
			// Verified already; skip actual verification.
			node = workflow.NewNodeSimple(&NodeVerifiedIdentity{
				IdentityID:       i.Identity.ID,
				NewVerifiedClaim: nil,
			})
			return nil
		}

		if i.IsCaptchaProtected && len(workflow.FindSubWorkflows[*IntentVerifyCaptcha](workflows.Nearest)) == 0 {
			node = workflow.NewSubWorkflow(&IntentVerifyCaptcha{})
			return nil
		}

		var nodeSimple interface {
			workflow.NodeSimple
			otpKind(deps *workflow.Dependencies) otp.Kind
			otpTarget() string
			sendCode(ctx context.Context, deps *workflow.Dependencies) error
		}

		switch model.ClaimName(status.Name) {
		case model.ClaimEmail:
			nodeSimple = &NodeVerifyEmail{
				UserID:     i.Identity.UserID,
				IdentityID: i.Identity.ID,
				Email:      status.Value,
			}

		case model.ClaimPhoneNumber:
			nodeSimple = &NodeVerifyPhoneSMS{
				UserID:      i.Identity.UserID,
				IdentityID:  i.Identity.ID,
				PhoneNumber: status.Value,
			}
		}
		if nodeSimple == nil {
			return api.ErrClaimNotVerifiable
		}

		kind := nodeSimple.otpKind(deps)
		err = nodeSimple.sendCode(ctx, deps)
		if ratelimit.IsRateLimitErrorWithBucketName(err, kind.RateLimitTriggerCooldown(nodeSimple.otpTarget()).Name) {
			// Ignore trigger cooldown rate limit error; continue the workflow
		} else if err != nil {
			return err
		}

		node = workflow.NewNodeSimple(nodeSimple)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return node, nil
}

func (*IntentVerifyIdentity) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return nil, nil
}

func (i *IntentVerifyIdentity) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return nil, nil
}

func (i *IntentVerifyIdentity) VerifiedIdentity(w *workflow.Workflow) (*NodeVerifiedIdentity, bool) {
	return workflow.FindSingleNode[*NodeVerifiedIdentity](w)
}
