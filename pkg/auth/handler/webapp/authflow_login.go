package webapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/webapp"
	"github.com/authgear/authgear-server/pkg/lib/authenticationflow/authflowclient"
	"github.com/authgear/authgear-server/pkg/lib/authn/sso"
	"github.com/authgear/authgear-server/pkg/lib/meter"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/httputil"
	"github.com/authgear/authgear-server/pkg/util/template"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

var TemplateWebAuthflowLoginHTML = template.RegisterHTML(
	"web/authflow_login.html",
	components...,
)

var AuthflowLoginLoginIDSchema = validation.NewSimpleSchema(`
	{
		"type": "object",
		"properties": {
			"q_login_id": { "type": "string" }
		},
		"required": ["q_login_id"]
	}
`)

func ConfigureAuthflowLoginRoute(route httproute.Route) httproute.Route {
	return route.
		WithMethods("OPTIONS", "POST", "GET").
		WithPathPattern(webapp.AuthflowRouteLogin)
}

type AuthflowLoginEndpointsProvider interface {
	SSOCallbackURL(alias string) *url.URL
}

type AuthflowLoginViewModel struct {
	AllowLoginOnly bool
}

func NewAuthflowLoginViewModel(allowLoginOnly bool) AuthflowLoginViewModel {
	return AuthflowLoginViewModel{
		AllowLoginOnly: allowLoginOnly,
	}
}

type AuthflowLoginHandler struct {
	Controller        *AuthflowController
	BaseViewModel     *viewmodels.BaseViewModeler
	AuthflowViewModel *viewmodels.AuthflowViewModeler
	Renderer          Renderer
	MeterService      MeterService
	TutorialCookie    TutorialCookie
	ErrorCookie       ErrorCookie
	Endpoints         AuthflowLoginEndpointsProvider
}

func (h *AuthflowLoginHandler) GetData(w http.ResponseWriter, r *http.Request, screen *webapp.AuthflowScreenWithFlowResponse, allowLoginOnly bool) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	baseViewModel := h.BaseViewModel.ViewModelForAuthFlow(r, w)
	if h.TutorialCookie.Pop(r, w, httputil.SignupLoginTutorialCookieName) {
		baseViewModel.SetTutorial(httputil.SignupLoginTutorialCookieName)
	}
	viewmodels.Embed(data, baseViewModel)
	authflowViewModel := h.AuthflowViewModel.NewWithAuthflow(screen.StateTokenFlowResponse, r)
	viewmodels.Embed(data, authflowViewModel)
	viewmodels.Embed(data, NewAuthflowLoginViewModel(allowLoginOnly))
	return data, nil
}

func (h *AuthflowLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flowName := "default"
	opts := webapp.SessionOptions{
		RedirectURI: h.Controller.RedirectURI(r),
	}

	oauthPostAction := func(s *webapp.Session, providerAlias string) error {
		callbackURL := h.Endpoints.SSOCallbackURL(providerAlias).String()
		input := map[string]interface{}{
			"identification": "oauth",
			"alias":          providerAlias,
			"redirect_uri":   callbackURL,
			"response_mode":  string(sso.ResponseModeFormPost),
		}

		result, err := h.Controller.ReplaceScreen(w, r, s, authflowclient.FlowReference{
			Type: authflowclient.FlowTypeSignupLogin,
			Name: flowName,
		}, input)
		if err != nil {
			return err
		}

		result.WriteResponse(w, r)
		return nil
	}

	var handlers AuthflowControllerHandlers
	handlers.Get(func(s *webapp.Session, screen *webapp.AuthflowScreenWithFlowResponse) error {
		oauthProviderAlias := s.OAuthProviderAlias
		allowLoginOnly := s.UserIDHint != ""

		visitorID := webapp.GetVisitorID(r.Context())
		if visitorID == "" {
			// visitor id should be generated by VisitorIDMiddleware
			return fmt.Errorf("webapp: missing visitor id")
		}

		err := h.MeterService.TrackPageView(visitorID, meter.PageTypeLogin)
		if err != nil {
			return err
		}

		_, hasErr := h.ErrorCookie.GetError(r)
		// If x_oauth_provider_alias is provided via authz endpoint
		// redirect the user to the oauth provider
		// If there is error in the ErrorCookie, the user will stay in the login
		// page to see the error message and the redirection won't be performed
		if !hasErr && oauthProviderAlias != "" {
			return oauthPostAction(s, oauthProviderAlias)
		}

		data, err := h.GetData(w, r, screen, allowLoginOnly)
		if err != nil {
			return err
		}

		h.Renderer.RenderHTML(w, r, TemplateWebAuthflowLoginHTML, data)
		return nil
	})

	handlers.PostAction("oauth", func(s *webapp.Session, _ *webapp.AuthflowScreenWithFlowResponse) error {
		providerAlias := r.Form.Get("x_provider_alias")
		return oauthPostAction(s, providerAlias)
	})

	handlers.PostAction("login_id", func(s *webapp.Session, screen *webapp.AuthflowScreenWithFlowResponse) error {
		err := AuthflowLoginLoginIDSchema.Validator().ValidateValue(FormToJSON(r.Form))
		if err != nil {
			return err
		}

		loginID := r.Form.Get("q_login_id")
		identification := webapp.GetMostAppropriateIdentification(screen.StateTokenFlowResponse, loginID)
		input := map[string]interface{}{
			"identification": identification,
			"login_id":       loginID,
		}

		result, err := h.Controller.AdvanceWithInput(w, r, s, screen, input)
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

		result, err := h.Controller.AdvanceWithInput(w, r, s, screen, input)
		if err != nil {
			return err
		}

		result.WriteResponse(w, r)
		return nil
	})

	h.Controller.HandleStartOfFlow(w, r, opts, authflowclient.FlowReference{
		Type: authflowclient.FlowTypeLogin,
		Name: flowName,
	}, &handlers)
}
