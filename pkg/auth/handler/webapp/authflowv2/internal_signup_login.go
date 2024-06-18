package authflowv2

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/authgear/oauthrelyingparty/pkg/api/oauthrelyingparty"

	handlerwebapp "github.com/authgear/authgear-server/pkg/auth/handler/webapp"
	v2viewmodels "github.com/authgear/authgear-server/pkg/auth/handler/webapp/authflowv2/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/webapp"
	authflow "github.com/authgear/authgear-server/pkg/lib/authenticationflow"
	"github.com/authgear/authgear-server/pkg/lib/meter"
	"github.com/authgear/authgear-server/pkg/util/httputil"
	"github.com/authgear/authgear-server/pkg/util/template"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

var TemplateWebAuthflowV2SignupHTML = template.RegisterHTML(
	"web/authflowv2/signup.html",
	handlerwebapp.Components...,
)

var AuthflowV2SignupLoginIDSchema = validation.NewSimpleSchema(`
	{
		"type": "object",
		"properties": {
			"q_login_id_key": { "type": "string" },
			"q_login_id": { "type": "string" }
		},
		"required": ["q_login_id_key", "q_login_id"]
	}
`)

type InternalAuthflowV2SignupLoginHandler struct {
	Controller        *handlerwebapp.AuthflowController
	BaseViewModel     *viewmodels.BaseViewModeler
	AuthflowViewModel *viewmodels.AuthflowViewModeler
	Renderer          handlerwebapp.Renderer
	MeterService      handlerwebapp.MeterService
	TutorialCookie    handlerwebapp.TutorialCookie
	Endpoints         handlerwebapp.AuthflowSignupEndpointsProvider
}

type AuthflowV2SignupUIVariant string

const (
	AuthflowV2SignupUIVariantSignup      AuthflowV2SignupUIVariant = "signup"
	AuthflowV2SignupUIVariantSignupLogin AuthflowV2SignupUIVariant = "signup_login"
)

type AuthflowV2SignupServeOptions struct {
	CanSwitchToLogin bool
	FlowType         authflow.FlowType
	UIVariant        AuthflowV2SignupUIVariant
}

type AuthflowV2SignupViewModel struct {
	CanSwitchToLogin bool
	UIVariant        AuthflowV2SignupUIVariant
}

func (h *InternalAuthflowV2SignupLoginHandler) GetData(w http.ResponseWriter, r *http.Request, screen *webapp.AuthflowScreenWithFlowResponse, options AuthflowV2SignupServeOptions) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	baseViewModel := h.BaseViewModel.ViewModelForAuthFlow(r, w)
	if h.TutorialCookie.Pop(r, w, httputil.SignupLoginTutorialCookieName) {
		baseViewModel.SetTutorial(httputil.SignupLoginTutorialCookieName)
	}
	viewmodels.Embed(data, baseViewModel)
	authflowViewModel := h.AuthflowViewModel.NewWithAuthflow(screen.StateTokenFlowResponse, r)
	viewmodels.Embed(data, authflowViewModel)
	viewmodels.Embed(data, v2viewmodels.NewOAuthErrorViewModel(baseViewModel.RawError))

	signupViewModel := AuthflowV2SignupViewModel{
		CanSwitchToLogin: options.CanSwitchToLogin,
		UIVariant:        options.UIVariant,
	}
	viewmodels.Embed(data, signupViewModel)

	return data, nil
}

func (h *InternalAuthflowV2SignupLoginHandler) GetInlinePreviewData(w http.ResponseWriter, r *http.Request, options AuthflowV2SignupServeOptions) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	baseViewModel := h.BaseViewModel.ViewModelForInlinePreviewAuthFlow(r, w)
	viewmodels.Embed(data, baseViewModel)
	authflowViewModel := h.AuthflowViewModel.NewWithConfig()
	viewmodels.Embed(data, authflowViewModel)
	viewmodels.Embed(data, v2viewmodels.NewOAuthErrorViewModel(baseViewModel.RawError))
	signupViewModel := AuthflowV2SignupViewModel{
		CanSwitchToLogin: options.CanSwitchToLogin,
		UIVariant:        options.UIVariant,
	}
	viewmodels.Embed(data, signupViewModel)
	return data, nil
}

func (h *InternalAuthflowV2SignupLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, options AuthflowV2SignupServeOptions) {
	if r.URL.Query().Get(webapp.PreviewQueryKey) == webapp.PreviewModeInline {
		var previewHandler handlerwebapp.PreviewHandler
		previewHandler.Preview(func() error {
			data, err := h.GetInlinePreviewData(w, r, options)
			if err != nil {
				return err
			}
			h.Renderer.RenderHTML(w, r, TemplateWebAuthflowV2SignupHTML, data)
			return nil
		})
		previewHandler.ServeHTTP(w, r)
		return
	}

	opts := webapp.SessionOptions{
		RedirectURI: h.Controller.RedirectURI(r),
	}

	var handlers handlerwebapp.AuthflowControllerHandlers
	handlers.Get(func(s *webapp.Session, screen *webapp.AuthflowScreenWithFlowResponse) error {
		visitorID := webapp.GetVisitorID(r.Context())
		if visitorID == "" {
			// visitor id should be generated by VisitorIDMiddleware
			return fmt.Errorf("webapp: missing visitor id")
		}

		err := h.MeterService.TrackPageView(visitorID, meter.PageTypeSignup)
		if err != nil {
			return err
		}

		data, err := h.GetData(w, r, screen, options)
		if err != nil {
			return err
		}

		h.Renderer.RenderHTML(w, r, TemplateWebAuthflowV2SignupHTML, data)
		return nil
	})

	handlers.PostAction("oauth", func(s *webapp.Session, screen *webapp.AuthflowScreenWithFlowResponse) error {
		providerAlias := r.Form.Get("x_provider_alias")
		callbackURL := h.Endpoints.SSOCallbackURL(providerAlias).String()
		input := map[string]interface{}{
			"identification": "oauth",
			"alias":          providerAlias,
			"redirect_uri":   callbackURL,
			"response_mode":  oauthrelyingparty.ResponseModeFormPost,
		}

		result, err := h.Controller.ReplaceScreen(r, s, authflow.FlowTypeSignupLogin, input)
		if err != nil {
			return err
		}
		result.WriteResponse(w, r)
		return nil
	})

	handlers.PostAction("login_id", func(s *webapp.Session, screen *webapp.AuthflowScreenWithFlowResponse) error {
		err := AuthflowV2SignupLoginIDSchema.Validator().ValidateValue(handlerwebapp.FormToJSON(r.Form))
		if err != nil {
			return err
		}

		loginIDKey := r.Form.Get("q_login_id_key")
		loginID := r.Form.Get("q_login_id")
		identification := loginIDKey
		input := map[string]interface{}{
			"identification": identification,
			"login_id":       loginID,
		}

		result, err := h.Controller.AdvanceWithInput(r, s, screen, input, nil)
		if err != nil {
			return err
		}

		result.WriteResponse(w, r)
		return nil
	})

	handlers.PostAction("passkey", func(s *webapp.Session, screen *webapp.AuthflowScreenWithFlowResponse) error {
		assertionResponseStr := r.Form.Get("x_assertion_response")

		var assertionResponseJSON interface{}
		err := json.Unmarshal([]byte(assertionResponseStr), &assertionResponseJSON)
		if err != nil {
			return err
		}

		input := map[string]interface{}{
			"identification":     "passkey",
			"assertion_response": assertionResponseJSON,
		}

		result, err := h.Controller.AdvanceWithInput(r, s, screen, input, nil)
		if err != nil {
			return err
		}

		result.WriteResponse(w, r)
		return nil
	})

	h.Controller.HandleStartOfFlow(w, r, opts, options.FlowType, &handlers, nil)
}
