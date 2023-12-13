package workflow

import (
	"context"
)

func WithRunEffects(ctx context.Context, deps *Dependencies, workflows Workflows, f func() error) error {
	err := deps.Database.ReadOnly(func() error {
		// Apply the run effects from root.
		effs, err := workflows.Root.CollectRunEffects(ctx, deps, NewWorkflows(workflows.Root))
		if err != nil {
			return err
		}

		for _, eff := range effs {
			err = applyRunEffect(ctx, deps, eff)
			if err != nil {
				return err
			}
		}

		err = f()
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}
