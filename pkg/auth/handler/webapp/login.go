package webapp

import (
	"fmt"
	"net/http"

	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/webapp"
	"github.com/authgear/authgear-server/pkg/lib/authn"
	"github.com/authgear/authgear-server/pkg/lib/interaction"
	"github.com/authgear/authgear-server/pkg/lib/interaction/intents"
	"github.com/authgear/authgear-server/pkg/lib/meter"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/httputil"
	"github.com/authgear/authgear-server/pkg/util/template"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

var TemplateWebLoginHTML = template.RegisterHTML(
	"web/login.html",
	components...,
)

var LoginWithLoginIDSchema = validation.NewSimpleSchema(`
	{
		"type": "object",
		"properties": {
			"q_login_id_input_type": { "type": "string", "enum": ["email", "phone", "text"] },
			"q_login_id": { "type": "string" }
		},
		"required": ["q_login_id_input_type", "q_login_id"]
	}
`)

var PasskeyAutofillSchema = validation.NewSimpleSchema(`
	{
		"type": "object",
		"properties": {
			"x_assertion_response": { "type": "string" }
		},
		"required": ["x_assertion_response"]
	}
`)

func ConfigureLoginRoute(route httproute.Route) httproute.Route {
	return route.
		WithMethods("OPTIONS", "POST", "GET").
		WithPathPattern("/login")
}

type TutorialCookie interface {
	Pop(r *http.Request, rw http.ResponseWriter, name httputil.TutorialCookieName) bool
}

type ErrorCookie interface {
	GetError(r *http.Request) (*webapp.ErrorState, bool)
}

type LoginViewModel struct {
	AllowLoginOnly   bool
	LoginIDInputType string
}

func NewLoginViewModel(allowLoginOnly bool, r *http.Request) LoginViewModel {
	loginIDInputType := r.Form.Get("q_login_id_input_type")
	return LoginViewModel{
		AllowLoginOnly:   allowLoginOnly,
		LoginIDInputType: loginIDInputType,
	}
}

type LoginHandler struct {
	ControllerFactory       ControllerFactory
	BaseViewModel           *viewmodels.BaseViewModeler
	AuthenticationViewModel *viewmodels.AuthenticationViewModeler
	FormPrefiller           *FormPrefiller
	Renderer                Renderer
	MeterService            MeterService
	TutorialCookie          TutorialCookie
	ErrorCookie             ErrorCookie
}

func (h *LoginHandler) GetData(r *http.Request, rw http.ResponseWriter, graph *interaction.Graph, allowLoginOnly bool) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	baseViewModel := h.BaseViewModel.ViewModel(r, rw)
	if h.TutorialCookie.Pop(r, rw, httputil.SignupLoginTutorialCookieName) {
		baseViewModel.SetTutorial(httputil.SignupLoginTutorialCookieName)
	}
	viewmodels.Embed(data, baseViewModel)
	authenticationViewModel := h.AuthenticationViewModel.NewWithGraph(graph, r.Form)
	viewmodels.Embed(data, authenticationViewModel)
	viewmodels.Embed(data, NewLoginViewModel(allowLoginOnly, r))
	return data, nil
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctrl, err := h.ControllerFactory.New(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ctrl.Serve()

	h.FormPrefiller.Prefill(r.Form)

	opts := webapp.SessionOptions{
		RedirectURI: ctrl.RedirectURI(),
	}

	userIDHint := ""
	webhookState := ""
	suppressIDPSessionCookie := false
	prompt := []string{}
	oauthProviderAlias := ""
	if s := webapp.GetSession(r.Context()); s != nil {
		webhookState = s.WebhookState
		prompt = s.Prompt
		userIDHint = s.UserIDHint
		suppressIDPSessionCookie = s.SuppressIDPSessionCookie
		oauthProviderAlias = s.OAuthProviderAlias
	}
	intent := &intents.IntentAuthenticate{
		Kind:                     intents.IntentAuthenticateKindLogin,
		WebhookState:             webhookState,
		UserIDHint:               userIDHint,
		SuppressIDPSessionCookie: suppressIDPSessionCookie,
		CancelURI:                r.URL.String(),
	}

	allowLoginOnly := intent.UserIDHint != ""

	oauthPostAction := func(providerAlias string) error {
		result, err := ctrl.EntryPointPost(opts, intent, func() (input interface{}, err error) {
			input = &InputUseOAuth{
				ProviderAlias:    providerAlias,
				ErrorRedirectURI: httputil.HostRelative(r.URL).String(),
				Prompt:           prompt,
			}
			return
		})
		if err != nil {
			return err
		}

		result.WriteResponse(w, r)
		return nil
	}

	ctrl.Get(func() error {
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
			return oauthPostAction(oauthProviderAlias)
		}

		graph, err := ctrl.EntryPointGet(opts, intent)
		if err != nil {
			return err
		}

		data, err := h.GetData(r, w, graph, allowLoginOnly)
		if err != nil {
			return err
		}

		h.Renderer.RenderHTML(w, r, TemplateWebLoginHTML, data)
		return nil
	})

	ctrl.PostAction("oauth", func() error {
		providerAlias := r.Form.Get("x_provider_alias")
		return oauthPostAction(providerAlias)
	})

	ctrl.PostAction("login_id", func() error {
		result, err := ctrl.EntryPointPost(opts, intent, func() (input interface{}, err error) {
			err = LoginWithLoginIDSchema.Validator().ValidateValue(FormToJSON(r.Form))
			if err != nil {
				return
			}

			loginID := r.Form.Get("q_login_id")

			input = &InputUseLoginID{
				LoginID: loginID,
			}
			return
		})
		if err != nil {
			return err
		}

		result.WriteResponse(w, r)
		return nil
	})

	ctrl.PostAction("passkey", func() error {
		result, err := ctrl.EntryPointPost(opts, intent, func() (input interface{}, err error) {
			err = PasskeyAutofillSchema.Validator().ValidateValue(FormToJSON(r.Form))
			if err != nil {
				return
			}

			assertionResponseStr := r.Form.Get("x_assertion_response")
			assertionResponse := []byte(assertionResponseStr)
			stage := string(authn.AuthenticationStagePrimary)

			input = &InputPasskeyAssertionResponse{
				Stage:             stage,
				AssertionResponse: assertionResponse,
			}
			return
		})
		if err != nil {
			return err
		}

		result.WriteResponse(w, r)
		return nil
	})
}
