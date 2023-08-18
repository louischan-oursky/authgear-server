package api

import (
	"net/http"

	workflow "github.com/authgear/authgear-server/pkg/lib/workflow2"
	"github.com/authgear/authgear-server/pkg/util/httputil"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

type Workflow2Response struct {
	Action     *workflow.WorkflowAction `json:"action"`
	WorkflowID string                   `json:"workflow_id"`
	InstanceID string                   `json:"instance_id"`
	Schema     validation.SchemaBuilder `json:"schema,omitempty"`
	Data       workflow.Data            `json:"data"`
}

type Workflow2UserAgentCookieManager interface {
	GetCookie(r *http.Request, def *httputil.CookieDef) (*http.Cookie, error)
	ValueCookie(def *httputil.CookieDef, value string) *http.Cookie
}

func workflow2getOrCreateUserAgentID(cookies Workflow2UserAgentCookieManager, w http.ResponseWriter, r *http.Request) string {
	var userAgentID string
	userAgentIDCookie, err := cookies.GetCookie(r, workflow.UserAgentIDCookieDef)
	if err == nil {
		userAgentID = userAgentIDCookie.Value
	}
	if userAgentID == "" {
		userAgentID = workflow.NewUserAgentID()
	}
	cookie := cookies.ValueCookie(workflow.UserAgentIDCookieDef, userAgentID)
	httputil.UpdateCookie(w, cookie)
	return userAgentID
}