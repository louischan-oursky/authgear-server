package portal

import (
	"net/http"

	graphqlhandler "github.com/graphql-go/handler"

	"github.com/authgear/authgear-server/pkg/portal/deps"
	"github.com/authgear/authgear-server/pkg/portal/transport"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/httputil"
)

func NewRouter(p *deps.RootProvider) *httproute.Router {
	router := httproute.NewRouter()

	router.Pprof()

	router.Add(httproute.Route{
		Methods:     []string{"GET"},
		PathPattern: "/healthz",
	}, http.HandlerFunc(httputil.HealthCheckHandler))

	securityMiddleware := httproute.Chain(
		httproute.MiddlewareFunc(httputil.StaticSecurityHeaders),
		httputil.StaticCSPHeader{
			CSPDirectives: []string{
				// FIXME(regeneratorRuntime)
				// parcel-2.0.0-rc.0 requires us to use ES6 module when the browser supports it.
				// ES6 module assumes strict mode.
				// regeneratorRuntime is not compatible with strict mode because
				// it uses Function to generate function, which is considered as eval.
				"script-src 'self' 'unsafe-eval' 'unsafe-inline' cdn.jsdelivr.net unpkg.com www.googletagmanager.com cdn.mxpnl.com",
				// monaco editor create worker with blob:
				"worker-src 'self' 'unsafe-inline' cdn.jsdelivr.net blob:",
				"object-src 'none'",
				"base-uri 'none'",
				"block-all-mixed-content",
				"frame-ancestors 'none'",
			},
		},
	)

	rootChain := httproute.Chain(
		p.Middleware(newPanicMiddleware),
		p.Middleware(newBodyLimitMiddleware),
		p.Middleware(newSentryMiddleware),
		p.Middleware(newSessionInfoMiddleware),
		securityMiddleware,
	)
	systemConfigJSONChain := httproute.Chain(
		rootChain,
		httproute.MiddlewareFunc(httputil.NoCache),
	)
	graphqlChain := httproute.Chain(
		rootChain,
		httproute.MiddlewareFunc(httputil.NoStore),
		httputil.CheckContentType([]string{
			graphqlhandler.ContentTypeJSON,
			graphqlhandler.ContentTypeGraphQL,
		}),
	)
	adminAPIChain := httproute.Chain(
		rootChain,
		httproute.MiddlewareFunc(httputil.NoStore),
		p.Middleware(newSessionRequiredMiddleware),
		httputil.CheckContentType([]string{
			graphqlhandler.ContentTypeJSON,
			graphqlhandler.ContentTypeGraphQL,
		}),
	)
	incomingWebhookChain := httproute.Chain(
		rootChain,
		httproute.MiddlewareFunc(httputil.NoStore),
	)
	notFoundChain := httproute.Chain(
		securityMiddleware,
	)

	systemConfigJSONRoute := httproute.Route{Middleware: systemConfigJSONChain}
	graphqlRoute := httproute.Route{Middleware: graphqlChain}
	adminAPIRoute := httproute.Route{Middleware: adminAPIChain}
	incomingWebhookRoute := httproute.Route{Middleware: incomingWebhookChain}
	notFoundRoute := httproute.Route{Middleware: notFoundChain}

	router.Add(transport.ConfigureSystemConfigRoute(systemConfigJSONRoute), p.Handler(newSystemConfigHandler))

	router.Add(transport.ConfigureGraphQLRoute(graphqlRoute), p.Handler(newGraphQLHandler))

	router.Add(transport.ConfigureAdminAPIRoute(adminAPIRoute), p.Handler(newAdminAPIHandler))

	router.Add(transport.ConfigureStripeWebhookRoute(incomingWebhookRoute), p.Handler(newStripeWebhookHandler))

	router.NotFound(notFoundRoute, p.Handler(newStaticAssetsHandler))

	return router
}
