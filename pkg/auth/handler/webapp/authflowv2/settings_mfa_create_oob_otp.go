package authflowv2

import (
	"net/http"
	"net/url"

	"github.com/authgear/authgear-server/pkg/api/model"
	handlerwebapp "github.com/authgear/authgear-server/pkg/auth/handler/webapp"
	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/webapp"
	"github.com/authgear/authgear-server/pkg/lib/accountmanagement"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/template"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

var TemplateWebSettingsMFACreateOOBOTPHTML = template.RegisterHTML(
	"web/authflowv2/settings_mfa_create_oob_otp.html",
	handlerwebapp.SettingsComponents...,
)

var AuthflowV2SettingsMFACreateOOBOTPSchema = validation.NewSimpleSchema(`
	{
		"type": "object",
		"properties": {
			"x_channel": { "type": "string" },
			"x_target": { "type": "string" }
		},
		"required": ["x_channel", "x_target"]
	}
`)

func ConfigureAuthflowV2SettingsMFACreateOOBOTPRoute(route httproute.Route) httproute.Route {
	return route.
		WithMethods("OPTIONS", "POST", "GET").
		WithPathPattern(AuthflowV2RouteSettingsMFACreateOOBOTP)
}

type SettingsMFACreateOOBOTPViewModel struct {
	Channel model.AuthenticatorOOBChannel
}

type AuthflowV2SettingsMFACreateOOBOTPHandler struct {
	ControllerFactory handlerwebapp.ControllerFactory
	BaseViewModel     *viewmodels.BaseViewModeler
	Renderer          handlerwebapp.Renderer

	AccountManagementService *accountmanagement.Service
}

func NewSettingsMFACreateOOBOTPViewModel(channel model.AuthenticatorOOBChannel) SettingsMFACreateOOBOTPViewModel {
	return SettingsMFACreateOOBOTPViewModel{
		Channel: channel,
	}
}

func (h *AuthflowV2SettingsMFACreateOOBOTPHandler) GetData(r *http.Request, w http.ResponseWriter, channel model.AuthenticatorOOBChannel) (map[string]interface{}, error) {
	data := make(map[string]interface{})

	baseViewModel := h.BaseViewModel.ViewModelForAuthFlow(r, w)
	viewmodels.Embed(data, baseViewModel)

	settingsViewModel := NewSettingsMFACreateOOBOTPViewModel(channel)
	viewmodels.Embed(data, settingsViewModel)

	return data, nil
}

func (h *AuthflowV2SettingsMFACreateOOBOTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctrl, err := h.ControllerFactory.New(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ctrl.ServeWithoutDBTx()

	ctrl.Get(func() error {
		channel := model.AuthenticatorOOBChannel(httproute.GetParam(r, "channel"))
		data, err := h.GetData(r, w, channel)
		if err != nil {
			return err
		}
		h.Renderer.RenderHTML(w, r, TemplateWebSettingsMFACreateOOBOTPHTML, data)
		return nil
	})

	ctrl.PostAction("", func() error {
		err := AuthflowV2SettingsMFACreateOOBOTPSchema.Validator().ValidateValue(handlerwebapp.FormToJSON(r.Form))
		if err != nil {
			return err
		}

		channel := model.AuthenticatorOOBChannel(r.Form.Get("x_channel"))
		target := r.Form.Get("x_target")

		s := session.GetSession(r.Context())
		output, err := h.AccountManagementService.StartAddOOBOTPAuthenticator(s, &accountmanagement.StartAddOOBOTPAuthenticatorInput{
			Channel: channel,
			Target:  target,
		})
		if err != nil {
			return err
		}

		redirectURI, err := url.Parse(AuthflowV2RouteSettingsMFAEnterOOBOTP)
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
}