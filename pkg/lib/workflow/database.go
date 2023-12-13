package workflow

import (
	"context"
)

func WithRunEffects(ctx context.Context, deps *Dependencies, workflows Workflows, f func() error) error {
	err := deps.Database.ReadOnly(func() error {
		// Apply the run effects from root.
		err := workflows.Root.ApplyRunEffects(ctx, deps, NewWorkflows(workflows.Root))
		if err != nil {
			return err
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
