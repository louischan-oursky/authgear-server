package oidc

import (
	"github.com/google/wire"
)

var DependencySet = wire.NewSet(
	wire.Struct(new(MetadataProvider), "*"),
	wire.Struct(new(IDTokenIssuer), "*"),
	wire.Bind(new(IDTokenHintResolverIssuer), new(*IDTokenIssuer)),
	wire.Struct(new(IDTokenHintResolver), "*"),
)
