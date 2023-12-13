package workflow

import (
	"context"
)

type EffectGetter interface {
	GetEffects(ctx context.Context, deps *Dependencies, workflows Workflows) (effs []Effect, err error)
}

type Effect interface {
	doNotCallThisDirectly(ctx context.Context, deps *Dependencies) error
}

type RunEffect func(ctx context.Context, deps *Dependencies) error

func (e RunEffect) doNotCallThisDirectly(ctx context.Context, deps *Dependencies) error {
	return e(ctx, deps)
}

func applyRunEffect(ctx context.Context, deps *Dependencies, eff RunEffect) error {
	return eff.doNotCallThisDirectly(ctx, deps)
}
