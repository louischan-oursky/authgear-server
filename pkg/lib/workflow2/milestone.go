package workflow2

// Milestone is a marker.
// The designed use case is to find out whether a particular milestone exists
// in the workflow, or any of its subworkflows.
type Milestone interface {
	Milestone()
}

func FindMilestone[T Milestone](w *Workflow) (T, bool) {
	var t T
	found := false

	err := TraverseWorkflow(WorkflowTraverser{
		NodeSimple: func(nodeSimple NodeSimple, _ *Workflow) error {
			if m, ok := nodeSimple.(T); ok {
				t = m
				found = true
			}
			return nil
		},
		Intent: func(intent Intent, w *Workflow) error {
			if m, ok := intent.(T); ok {
				t = m
				found = true
			}
			return nil
		},
	}, w)
	if err != nil {
		return *new(T), false
	}

	if !found {
		return *new(T), false
	}

	return t, true
}