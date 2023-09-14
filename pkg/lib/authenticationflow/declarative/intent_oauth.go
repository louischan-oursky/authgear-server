package declarative

import (
	"context"

	"github.com/iawaknahc/jsonschema/pkg/jsonpointer"

	authflow "github.com/authgear/authgear-server/pkg/lib/authenticationflow"
	"github.com/authgear/authgear-server/pkg/lib/config"
)

func init() {
	authflow.RegisterIntent(&IntentOAuth{})
}

type IntentOAuth struct {
	JSONPointer    jsonpointer.T                           `json:"json_pointer,omitempty"`
	NewUserID      string                                  `json:"new_user_id,omitempty"`
	Identification config.AuthenticationFlowIdentification `json:"identification,omitempty"`
}

var _ authflow.Intent = &IntentOAuth{}
var _ authflow.Milestone = &IntentOAuth{}
var _ MilestoneIdentificationMethod = &IntentOAuth{}

func (*IntentOAuth) Kind() string {
	return "IntentOAuth"
}

func (*IntentOAuth) Milestone() {}
func (i *IntentOAuth) MilestoneIdentificationMethod() config.AuthenticationFlowIdentification {
	return i.Identification
}

func (i *IntentOAuth) CanReactTo(ctx context.Context, deps *authflow.Dependencies, flows authflow.Flows) (authflow.InputSchema, error) {
	if len(flows.Nearest.Nodes) == 0 {
		oauthCandidates := NewIdentificationCandidatesOAuth(deps.Config.Identity.OAuth, deps.FeatureConfig.Identity.OAuth.Providers)
		return &InputSchemaTakeOAuthAuthorizationRequest{
			JSONPointer:     i.JSONPointer,
			OAuthCandidates: oauthCandidates,
		}, nil
	}
	return nil, authflow.ErrEOF
}

func (i *IntentOAuth) ReactTo(ctx context.Context, deps *authflow.Dependencies, flows authflow.Flows, input authflow.Input) (*authflow.Node, error) {
	if len(flows.Nearest.Nodes) == 0 {
		var inputOAuth inputTakeOAuthAuthorizationRequest
		if authflow.AsInput(input, &inputOAuth) {
			alias := inputOAuth.GetOAuthAlias()
			state := inputOAuth.GetOAuthState()
			redirectURI := inputOAuth.GetOAuthRedirectURI()

			return authflow.NewNodeSimple(&NodeOAuth{
				JSONPointer: i.JSONPointer,
				NewUserID:   i.NewUserID,
				Alias:       alias,
				State:       state,
				RedirectURI: redirectURI,
			}), nil
		}
	}
	return nil, authflow.ErrIncompatibleInput
}