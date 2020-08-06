package oauth

import (
	"time"

	"github.com/authgear/authgear-server/pkg/auth/dependency/auth"
	"github.com/authgear/authgear-server/pkg/auth/model"
	"github.com/authgear/authgear-server/pkg/core/authn"
)

type OfflineGrant struct {
	AppID           string `json:"app_id"`
	ID              string `json:"id"`
	ClientID        string `json:"client_id"`
	AuthorizationID string `json:"authz_id"`

	CreatedAt time.Time `json:"created_at"`
	ExpireAt  time.Time `json:"expire_at"`
	Scopes    []string  `json:"scopes"`
	TokenHash string    `json:"token_hash"`

	Attrs      authn.Attrs     `json:"attrs"`
	AccessInfo auth.AccessInfo `json:"access_info"`
}

var _ Grant = &OfflineGrant{}
var _ auth.AuthSession = &OfflineGrant{}

func (g *OfflineGrant) Session() (kind GrantSessionKind, id string) {
	return GrantSessionKindOffline, g.ID
}

func (g *OfflineGrant) SessionID() string              { return g.ID }
func (g *OfflineGrant) SessionType() authn.SessionType { return auth.SessionTypeOfflineGrant }

func (g *OfflineGrant) AuthnAttrs() *authn.Attrs {
	return &g.Attrs
}

func (g *OfflineGrant) GetCreatedAt() time.Time         { return g.CreatedAt }
func (g *OfflineGrant) GetClientID() string             { return g.ClientID }
func (g *OfflineGrant) GetAccessInfo() *auth.AccessInfo { return &g.AccessInfo }

func (g *OfflineGrant) ToAPIModel() *model.Session {
	ua := model.ParseUserAgent(g.AccessInfo.LastAccess.UserAgent)
	ua.DeviceName = g.AccessInfo.LastAccess.Extra.DeviceName()
	amr, _ := g.Attrs.GetAMR()
	acr, _ := g.Attrs.GetACR()
	return &model.Session{
		ID: g.ID,

		AMR: amr,
		ACR: acr,

		CreatedAt:        g.CreatedAt,
		LastAccessedAt:   g.AccessInfo.LastAccess.Timestamp,
		CreatedByIP:      g.AccessInfo.InitialAccess.RemoteIP,
		LastAccessedByIP: g.AccessInfo.LastAccess.RemoteIP,
		UserAgent:        ua,
	}
}
