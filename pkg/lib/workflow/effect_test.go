package workflow

import (
	"context"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestCollectRunEffects(t *testing.T) {
	Convey("CollectRunEffects", t, func() {
		test := func(w *Workflow, expectedEffect string) {
			var buf strings.Builder
			ctx := context.Background()
			ctx = WithEffectWriter(ctx, &buf)
			deps := &Dependencies{}
			effs, err := w.CollectRunEffects(ctx, deps, NewWorkflows(w))
			So(err, ShouldBeNil)
			for _, eff := range effs {
				err = applyRunEffect(ctx, deps, eff)
				So(err, ShouldBeNil)
			}
			So(buf.String(), ShouldEqual, expectedEffect)
		}

		test(&Workflow{
			WorkflowID: "wf-0",
			InstanceID: "wf-0-instance-0",
			Intent: &testMarshalIntent0{
				Intent0: "intent0-0",
			},
			Nodes: []Node{
				Node{
					Type: NodeTypeSimple,
					Simple: &testMarshalNode0{
						Node0: "node0-0",
					},
				},
				Node{
					Type: NodeTypeSubWorkflow,
					SubWorkflow: &Workflow{
						Intent: &testMarshalIntent0{
							Intent0: "intent0-1",
						},
						Nodes: []Node{
							Node{
								Type: NodeTypeSimple,
								Simple: &testMarshalNode0{
									Node0: "node0-1",
								},
							},
						},
					},
				},
				Node{
					Type: NodeTypeSimple,
					Simple: &testMarshalNode0{
						Node0: "node0-2",
					},
				},
			},
		}, `run-effect: node0-0
run-effect: node0-1
run-effect: node0-2
`)
	})
}
