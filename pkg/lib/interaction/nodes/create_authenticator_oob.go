package nodes

import (
	"github.com/authgear/authgear-server/pkg/lib/authn"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/interaction"
)

func init() {
	interaction.RegisterNode(&NodeCreateAuthenticatorOOB{})
}

type InputCreateAuthenticatorOOB interface {
	GetOOBOTP() string
}

type EdgeCreateAuthenticatorOOB struct {
	Stage         authn.AuthenticationStage
	Authenticator *authenticator.Info
}

func (e *EdgeCreateAuthenticatorOOB) Instantiate(ctx *interaction.Context, graph *interaction.Graph, rawInput interface{}) (interaction.Node, error) {
	var input InputCreateAuthenticatorOOB
	if !interaction.Input(rawInput, &input) {
		return nil, interaction.ErrIncompatibleInput
	}
	_, err := ctx.Authenticators.VerifyWithSpec(e.Authenticator, &authenticator.Spec{
		OOBOTP: &authenticator.OOBOTPSpec{
			Code: input.GetOOBOTP(),
		},
	}, nil)
	if err != nil {
		return nil, err
	}

	return &NodeCreateAuthenticatorOOB{Stage: e.Stage, Authenticator: e.Authenticator}, nil
}

type NodeCreateAuthenticatorOOB struct {
	Stage         authn.AuthenticationStage `json:"stage"`
	Authenticator *authenticator.Info       `json:"authenticator"`
}

func (n *NodeCreateAuthenticatorOOB) Prepare(ctx *interaction.Context, graph *interaction.Graph) error {
	return nil
}

func (n *NodeCreateAuthenticatorOOB) GetEffects() ([]interaction.Effect, error) {
	return nil, nil
}

func (n *NodeCreateAuthenticatorOOB) DeriveEdges(graph *interaction.Graph) ([]interaction.Edge, error) {
	return []interaction.Edge{
		&EdgeCreateAuthenticatorEnd{
			Stage:          n.Stage,
			Authenticators: []*authenticator.Info{n.Authenticator},
		},
	}, nil
}
