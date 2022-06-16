package graphql

import (
	"github.com/authgear/authgear-server/pkg/api/apierrors"
	"github.com/authgear/authgear-server/pkg/portal/libstripe"
	"github.com/authgear/authgear-server/pkg/portal/model"
	"github.com/authgear/authgear-server/pkg/portal/session"
	"github.com/authgear/authgear-server/pkg/util/graphqlutil"
	relay "github.com/authgear/graphql-go-relay"
	"github.com/graphql-go/graphql"
)

var subscribePlanInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "SubscribePlanInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"appID": &graphql.InputObjectFieldConfig{
			Type:        graphql.NewNonNull(graphql.ID),
			Description: "App ID.",
		},
		"stripeProductID": &graphql.InputObjectFieldConfig{
			Type:        graphql.NewNonNull(graphql.String),
			Description: "Stripe Product ID.",
		},
	},
})

var subscribePlanPayload = graphql.NewObject(graphql.ObjectConfig{
	Name: "SubscribePlanPayload",
	Fields: graphql.Fields{
		"url": &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
	},
})

var _ = registerMutationField(
	"subscribePlan",
	&graphql.Field{
		Description: "Subscribe to a plan",
		Type:        graphql.NewNonNull(subscribePlanPayload),
		Args: graphql.FieldConfigArgument{
			"input": &graphql.ArgumentConfig{
				Type: graphql.NewNonNull(subscribePlanInput),
			},
		},
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			// Access Control: authenticated user.
			sessionInfo := session.GetValidSessionInfo(p.Context)
			if sessionInfo == nil {
				return nil, AccessDenied.New("only authenticated users can subscribe to a plan")
			}

			input := p.Args["input"].(map[string]interface{})
			appNodeID := input["appID"].(string)
			stripeProductID := input["stripeProductID"].(string)

			resolvedNodeID := relay.FromGlobalID(appNodeID)
			if resolvedNodeID.Type != typeApp {
				return nil, apierrors.NewInvalid("invalid app ID")
			}
			appID := resolvedNodeID.ID
			gqlCtx := GQLContext(p.Context)
			// Access Control: collaborator.
			_, err := gqlCtx.AuthzService.CheckAccessOfViewer(appID)
			if err != nil {
				return nil, err
			}

			// fetch the subscription plan
			ctx := GQLContext(p.Context)
			plans, err := ctx.StripeService.FetchSubscriptionPlans()
			if err != nil {
				return nil, err
			}
			var plan *libstripe.SubscriptionPlan
			for _, p := range plans {
				if p.StripeProductID == stripeProductID {
					plan = p
					break
				}
			}
			if plan == nil {
				return nil, apierrors.NewInvalid("invalid stripe product id")
			}

			// fetch the current user email
			val, err := ctx.Users.Load(sessionInfo.UserID).Value()
			if err != nil {
				return nil, apierrors.NewInvalid("failed to load current user")
			}
			user, ok := val.(*model.User)
			if !ok {
				return nil, apierrors.NewInvalid("failed to load current user")
			}

			// create the checkout session
			url, err := ctx.StripeService.CreateCheckoutSession(appID, user.Email, plan)
			if err != nil {
				return nil, err
			}
			return graphqlutil.NewLazyValue(map[string]interface{}{
				"url": url,
			}).Value, nil
		},
	},
)
