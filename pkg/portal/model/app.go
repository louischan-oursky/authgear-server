package model

import (
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/portal/util/resources"
)

type App struct {
	ID      string
	Context *config.AppContext
}

type AppResource struct {
	resources.Resource
	Context *config.AppContext
}
