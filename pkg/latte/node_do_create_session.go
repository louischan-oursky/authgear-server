package latte

import (
	"context"
	"net/http"

	"github.com/authgear/authgear-server/pkg/lib/authn/authenticationinfo"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/lib/session/idpsession"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
)

func init() {
	workflow.RegisterNode(&NodeDoCreateSession{})
}

var _ workflow.CookieGetter = &NodeDoCreateSession{}

type NodeDoCreateSession struct {
	UserID                   string                    `json:"user_id"`
	CreateReason             session.CreateReason      `json:"create_reason"`
	Session                  *idpsession.IDPSession    `json:"session,omitempty"`
	AuthenticationInfoEntry  *authenticationinfo.Entry `json:"authentication_info_entry,omitempty"`
	SessionCookie            *http.Cookie              `json:"session_cookie,omitempty"`
	SameSiteStrictCookie     *http.Cookie              `json:"same_site_strict_cookie,omitempty"`
	AuthenticationInfoCookie *http.Cookie              `json:"authentication_info_cookie,omitempty"`
}

func (n *NodeDoCreateSession) Kind() string {
	return "latte.NodeDoCreateSession"
}

func (n *NodeDoCreateSession) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return []workflow.Effect{
		workflow.OnCommitEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			return deps.AuthenticationInfos.Save(n.AuthenticationInfoEntry)
		}),
		workflow.OnCommitEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			now := deps.Clock.NowUTC()
			return deps.Users.UpdateLoginTime(n.UserID, now)
		}),
		workflow.OnCommitEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			if n.Session == nil {
				return nil
			}

			err := deps.IDPSessions.Create(n.Session)
			if err != nil {
				return err
			}

			s := session.GetSession(ctx)
			if s != nil && s.SessionType() == session.TypeIdentityProvider {
				err = deps.Sessions.RevokeWithoutEvent(s)
				if err != nil {
					return err
				}
			}

			return nil
		}),
	}, nil
}

func (n *NodeDoCreateSession) GetCookies(ctx context.Context, deps *workflow.Dependencies, workfloworkflows workflow.Workflows) ([]*http.Cookie, error) {
	var cookies []*http.Cookie
	if n.SessionCookie != nil {
		cookies = append(cookies, n.SessionCookie)
	}
	if n.SameSiteStrictCookie != nil {
		cookies = append(cookies, n.SameSiteStrictCookie)
	}
	if n.AuthenticationInfoCookie != nil {
		cookies = append(cookies, n.AuthenticationInfoCookie)
	}
	return cookies, nil
}

func (*NodeDoCreateSession) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	return nil, workflow.ErrEOF
}

func (*NodeDoCreateSession) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	return nil, workflow.ErrIncompatibleInput
}

func (n *NodeDoCreateSession) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return nil, nil
}
