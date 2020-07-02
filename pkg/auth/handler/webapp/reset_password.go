package webapp

import (
	"net/http"

	"github.com/authgear/authgear-server/pkg/db"
	"github.com/authgear/authgear-server/pkg/httproute"
)

func ConfigureResetPasswordRoute(route httproute.Route) httproute.Route {
	return route.
		WithMethods("OPTIONS", "POST", "GET").
		WithPathPattern("/reset_password")
}

type ResetPasswordProvider interface {
	GetResetPasswordForm(w http.ResponseWriter, r *http.Request) (func(error), error)
	PostResetPasswordForm(w http.ResponseWriter, r *http.Request) (func(error), error)
}

type ResetPasswordHandler struct {
	Provider  ResetPasswordProvider
	DBContext db.Context
}

func (h *ResetPasswordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.DBContext.WithTx(func() error {
		if r.Method == "GET" {
			writeResponse, err := h.Provider.GetResetPasswordForm(w, r)
			writeResponse(err)
			return err
		}

		if r.Method == "POST" {
			writeResponse, err := h.Provider.PostResetPasswordForm(w, r)
			writeResponse(err)
			return err
		}
		return nil
	})
}
