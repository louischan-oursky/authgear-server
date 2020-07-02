package webapp

import (
	"net/http"

	"github.com/authgear/authgear-server/pkg/auth/config"
	"github.com/authgear/authgear-server/pkg/auth/dependency/auth"
	"github.com/authgear/authgear-server/pkg/auth/dependency/webapp"
	"github.com/authgear/authgear-server/pkg/db"
	"github.com/authgear/authgear-server/pkg/httproute"
)

func ConfigureLogoutRoute(route httproute.Route) httproute.Route {
	return route.
		WithMethods("OPTIONS", "POST", "GET").
		WithPathPattern("/logout")
}

type LogoutSessionManager interface {
	Logout(auth.AuthSession, http.ResponseWriter) error
}

type LogoutHandler struct {
	ServerConfig   *config.ServerConfig
	RenderProvider webapp.RenderProvider
	SessionManager LogoutSessionManager
	DBContext      db.Context
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.DBContext.WithTx(func() error {
		if r.Method == "POST" && r.Form.Get("x_action") == "logout" {
			sess := auth.GetSession(r.Context())
			h.SessionManager.Logout(sess, w)
			webapp.RedirectToRedirectURI(w, r, h.ServerConfig.TrustProxy)
		} else {
			h.RenderProvider.WritePage(w, r, webapp.TemplateItemTypeAuthUILogoutHTML, nil)
		}
		return nil
	})
}
