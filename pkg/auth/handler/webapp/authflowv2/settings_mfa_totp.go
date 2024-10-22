package authflowv2

import (
	"net/http"
	"net/url"

	"github.com/authgear/authgear-server/pkg/api/model"
	handlerwebapp "github.com/authgear/authgear-server/pkg/auth/handler/webapp"
	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/webapp"
	"github.com/authgear/authgear-server/pkg/lib/accountmanagement"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	authenticatorservice "github.com/authgear/authgear-server/pkg/lib/authn/authenticator/service"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/util/httputil"
	"github.com/authgear/authgear-server/pkg/util/template"
)

var TemplateWebSettingsTOTPHTML = template.RegisterHTML(
	"web/authflowv2/settings_mfa_totp.html",
	handlerwebapp.SettingsComponents...,
)

type AuthflowV2SettingsTOTPViewModel struct {
	TOTPAuthenticators []*authenticator.TOTP
}

type AuthflowV2SettingsTOTPHandler struct {
	Database          *appdb.Handle
	ControllerFactory handlerwebapp.ControllerFactory
	BaseViewModel     *viewmodels.BaseViewModeler
	SettingsViewModel *viewmodels.SettingsViewModeler
	Renderer          handlerwebapp.Renderer

	AccountManagement *accountmanagement.Service
	Authenticators    authenticatorservice.Service
}

func (h *AuthflowV2SettingsTOTPHandler) GetData(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	data := map[string]interface{}{}
	userID := session.GetUserID(r.Context())

	// BaseViewModel
	baseViewModel := h.BaseViewModel.ViewModel(r, w)
	viewmodels.Embed(data, baseViewModel)

	// SettingsViewModel
	settingsViewModel, err := h.SettingsViewModel.ViewModel(*userID)
	if err != nil {
		return nil, err
	}
	viewmodels.Embed(data, *settingsViewModel)

	authenticators, err := h.Authenticators.List(
		*userID,
		authenticator.KeepKind(authenticator.KindSecondary),
		authenticator.KeepType(model.AuthenticatorTypeTOTP),
	)

	if err != nil {
		return nil, err
	}

	var totpAuthenticators []*authenticator.TOTP
	for _, a := range authenticators {
		totpAuthenticators = append(totpAuthenticators, a.TOTP)
	}

	vm := AuthflowV2SettingsTOTPViewModel{
		TOTPAuthenticators: totpAuthenticators,
	}
	viewmodels.Embed(data, vm)

	return data, nil
}

func (h *AuthflowV2SettingsTOTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctrl, err := h.ControllerFactory.New(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ctrl.ServeWithoutDBTx()

	ctrl.Get(func() error {
		var data map[string]interface{}
		err := h.Database.WithTx(func() error {
			data, err = h.GetData(w, r)
			return err
		})
		if err != nil {
			return err
		}

		h.Renderer.RenderHTML(w, r, TemplateWebSettingsTOTPHTML, data)
		return nil
	})

	ctrl.PostAction("create_totp", func() error {
		s := session.GetSession(r.Context())
		output, err := h.AccountManagement.StartAddTOTPAuthenticator(s, &accountmanagement.StartAddTOTPAuthenticatorInput{})
		if err != nil {
			return err
		}

		redirectURI, err := url.Parse(AuthflowV2RouteSettingsMFACreateTOTP)
		if err != nil {
			return err
		}

		q := redirectURI.Query()
		q.Set("q_token", output.Token)

		redirectURI.RawQuery = q.Encode()

		result := webapp.Result{RedirectURI: redirectURI.String()}
		result.WriteResponse(w, r)

		return nil
	})

	ctrl.PostAction("remove", func() error {
		authenticatorID := r.Form.Get("x_authenticator_id")

		s := session.GetSession(r.Context())

		input := &accountmanagement.DeleteTOTPAuthenticatorInput{
			AuthenticatorID: authenticatorID,
		}
		_, err = h.AccountManagement.DeleteTOTPAuthenticator(s, input)
		if err != nil {
			return err
		}

		redirectURI := httputil.HostRelative(r.URL).String()
		result := webapp.Result{RedirectURI: redirectURI}
		result.WriteResponse(w, r)

		return nil
	})
}