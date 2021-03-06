package oauth

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	pkg "github.com/skygeario/skygear-server/pkg/auth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/handler"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/protocol"
	"github.com/skygeario/skygear-server/pkg/core/db"
)

func AttachAuthorizeHandler(
	router *mux.Router,
	authDependency pkg.DependencyMap,
) {
	router.NewRoute().
		Path("/oauth2/authorize").
		Handler(pkg.MakeHandler(authDependency, newAuthorizeHandler)).
		Methods("GET", "POST")
}

type oauthAuthorizeHandler interface {
	Handle(r protocol.AuthorizationRequest) handler.AuthorizationResult
}

var errAuthzInternalError = errors.New("internal error")

type AuthorizeHandler struct {
	logger       *logrus.Entry
	txContext    db.TxContext
	authzHandler oauthAuthorizeHandler
}

func (h *AuthorizeHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}

	req := protocol.AuthorizationRequest{}
	for name, values := range r.Form {
		req[name] = values[0]
	}

	var result handler.AuthorizationResult
	err = db.WithTx(h.txContext, func() error {
		result = h.authzHandler.Handle(req)
		if result.IsInternalError() {
			return errAuthzInternalError
		}
		return nil
	})

	if err == nil || errors.Is(err, errAuthzInternalError) {
		result.WriteResponse(rw, r)
	} else {
		h.logger.WithError(err).Error("oauth authz handler failed")
		http.Error(rw, "Internal Server Error", 500)
	}
}
