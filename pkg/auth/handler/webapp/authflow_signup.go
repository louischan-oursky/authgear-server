package webapp

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/webapp"
	authflow "github.com/authgear/authgear-server/pkg/lib/authenticationflow"
	"github.com/authgear/authgear-server/pkg/lib/authn/sso"
	"github.com/authgear/authgear-server/pkg/lib/meter"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/httputil"
	"github.com/authgear/authgear-server/pkg/util/template"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

var TemplateWebAuthflowSignupHTML = template.RegisterHTML(
	"web/authflow_signup.html",
	components...,
)

var AuthflowSignupLoginIDSchema = validation.NewSimpleSchema(`
	{
		"type": "object",
		"properties": {
			"q_login_id_key": { "type": "string" },
			"q_login_id": { "type": "string" }
		},
		"required": ["q_login_id_key", "q_login_id"]
	}
`)

func ConfigureAuthflowSignupRoute(route httproute.Route) httproute.Route {
	return route.
		WithMethods("OPTIONS", "POST", "GET").
		WithPathPattern(webapp.AuthflowRouteSignup)
}

type AuthflowSignupEndpointsProvider interface {
	SSOCallbackURL(alias string) *url.URL
}

type AuthflowSignupHandler struct {
	Controller        *AuthflowController
	BaseViewModel     *viewmodels.BaseViewModeler
	AuthflowViewModel *viewmodels.AuthflowViewModeler
	Renderer          Renderer
	MeterService      MeterService
	TutorialCookie    TutorialCookie
	ErrorCookie       ErrorCookie
	Endpoints         AuthflowSignupEndpointsProvider
}

func (h *AuthflowSignupHandler) GetData(w http.ResponseWriter, r *http.Request, screen *webapp.AuthflowScreenWithFlowResponse) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	baseViewModel := h.BaseViewModel.ViewModel(r, w)
	if h.TutorialCookie.Pop(r, w, httputil.SignupLoginTutorialCookieName) {
		baseViewModel.SetTutorial(httputil.SignupLoginTutorialCookieName)
	}
	viewmodels.Embed(data, baseViewModel)
	authflowViewModel := h.AuthflowViewModel.NewWithAuthflow(screen.StateTokenFlowResponse, r)
	viewmodels.Embed(data, authflowViewModel)
	return data, nil
}

func (h *AuthflowSignupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flowName := "default"
	opts := webapp.SessionOptions{
		RedirectURI: h.Controller.RedirectURI(r),
	}

	var handlers AuthflowControllerHandlers
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

		data, err := h.GetData(w, r, screen)
		if err != nil {
			return err
		}

		h.Renderer.RenderHTML(w, r, TemplateWebAuthflowSignupHTML, data)
		return nil
	})

	handlers.PostAction("oauth", func(s *webapp.Session, screen *webapp.AuthflowScreenWithFlowResponse) error {
		providerAlias := r.Form.Get("x_provider_alias")
		callbackURL := h.Endpoints.SSOCallbackURL(providerAlias).String()
		input := map[string]interface{}{
			"identification": "oauth",
			"alias":          providerAlias,
			"redirect_uri":   callbackURL,
			"response_mode":  string(sso.ResponseModeFormPost),
		}

		result, err := h.Controller.ReplaceScreen(r, s, authflow.FlowReference{
			Type: authflow.FlowTypeSignupLogin,
			Name: flowName,
		}, input)
		if err != nil {
			return err
		}
		result.WriteResponse(w, r)
		return nil
	})

	handlers.PostAction("login_id", func(s *webapp.Session, screen *webapp.AuthflowScreenWithFlowResponse) error {
		err := AuthflowSignupLoginIDSchema.Validator().ValidateValue(FormToJSON(r.Form))
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

		result, err := h.Controller.FeedInput(r, s, screen, input)
		if err != nil {
			return err
		}

		result.WriteResponse(w, r)
		return nil
	})

	h.Controller.HandleLoginFlowSignupFlowSignupLoginFlow(w, r, opts, authflow.FlowReference{
		Type: authflow.FlowTypeSignup,
		Name: flowName,
	}, &handlers)
}
