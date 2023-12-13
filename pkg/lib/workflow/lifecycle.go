package workflow

import (
	"context"
)

type BeforeCommit interface {
	BeforeCommit(ctx context.Context, deps *Dependencies, workflows Workflows) (effs []Effect, err error)
}

type AfterCommit interface {
	AfterCommit(ctx context.Context, deps *Dependencies, workflows Workflows) error
}

func RunBeforeCommit(ctx context.Context, deps *Dependencies, workflows Workflows) (runEffects []RunEffect, err error) {
	w := workflows.Root
	err = w.Traverse(WorkflowTraverser{
		NodeSimple: func(nodeSimple NodeSimple, w *Workflow) error {
			if lifecycle, ok := nodeSimple.(BeforeCommit); ok {
				effs, err := lifecycle.BeforeCommit(ctx, deps, workflows.Replace(w))
				if err != nil {
					return err
				}

				for _, eff := range effs {
					if runEff, ok := eff.(RunEffect); ok {
						runEffects = append(runEffects, runEff)
					}
				}
			}
			return nil
		},
		Intent: func(intent Intent, w *Workflow) error {
			if lifecycle, ok := intent.(BeforeCommit); ok {
				effs, err := lifecycle.BeforeCommit(ctx, deps, workflows.Replace(w))
				if err != nil {
					return err
				}

				for _, eff := range effs {
					if runEff, ok := eff.(RunEffect); ok {
						runEffects = append(runEffects, runEff)
					}
				}
			}
			return nil
		},
	})
	if err != nil {
		return
	}
	return
}

func RunAfterCommit(ctx context.Context, deps *Dependencies, workflows Workflows) error {
	w := workflows.Root
	err := w.Traverse(WorkflowTraverser{
		NodeSimple: func(nodeSimple NodeSimple, w *Workflow) error {
			if lifecycle, ok := nodeSimple.(AfterCommit); ok {
				err := lifecycle.AfterCommit(ctx, deps, workflows.Replace(w))
				if err != nil {
					return err
				}
			}
			return nil
		},
		Intent: func(intent Intent, w *Workflow) error {
			if lifecycle, ok := intent.(AfterCommit); ok {
				err := lifecycle.AfterCommit(ctx, deps, workflows.Replace(w))
				if err != nil {
					return err
				}
			}
			return nil
		},
	})
	if err != nil {
		return err
	}
	return nil
}
