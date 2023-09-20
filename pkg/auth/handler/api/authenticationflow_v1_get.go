package api

import (
	"net/http"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/lib/infra/redis/appredis"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/httputil"
	"github.com/authgear/authgear-server/pkg/util/log"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

func ConfigureAuthenticationFlowV1GetRoute(route httproute.Route) httproute.Route {
	return route.WithMethods("OPTIONS", "POST").WithPathPattern("/api/v1/authentication_flows/states")
}

type AuthenticationFlowV1NonRestfulGetRequest struct {
	StateID string `json:"state_id,omitempty"`
}

var AuthenticationFlowV1NonRestfulGetRequestSchema = validation.NewSimpleSchema(`
	{
		"type": "object",
		"properties": {
			"state_id": { "type": "string" }
		},
		"required": ["state_id"]
	}
`)

type AuthenticationFlowV1GetHandler struct {
	LoggerFactory *log.Factory
	RedisHandle   *appredis.Handle
	JSON          JSONResponseWriter
	Workflows     AuthenticationFlowV1WorkflowService
}

func (h *AuthenticationFlowV1GetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	var request AuthenticationFlowV1NonRestfulGetRequest
	err = httputil.BindJSONBody(r, w, AuthenticationFlowV1NonRestfulGetRequestSchema.Validator(), &request)
	if err != nil {
		h.JSON.WriteResponse(w, &api.Response{Error: err})
		return
	}

	stateID := request.StateID
	h.get(w, r, stateID)
}

func (h *AuthenticationFlowV1GetHandler) get(w http.ResponseWriter, r *http.Request, stateID string) {
	output, err := h.Workflows.Get(stateID)
	if err != nil {
		h.JSON.WriteResponse(w, &api.Response{Error: err})
		return
	}

	result := output.ToFlowResponse()
	h.JSON.WriteResponse(w, &api.Response{Result: result})
}
