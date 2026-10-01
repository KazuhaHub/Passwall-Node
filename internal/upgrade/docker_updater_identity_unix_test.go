//go:build unix

package upgrade

import (
	"encoding/json"
	"errors"
	"testing"
)

// mutations are the engine calls that change something; inspects do not count.
func mutations(engine *fakeDockerEngine) []fakeOp {
	var out []fakeOp
	for _, op := range engine.opLog() {
		switch op.op {
		case "create", "start", "stop", "rename", "remove":
			out = append(out, op)
		}
	}
	return out
}

// THE HANDOVER CANNOT TOUCH THE AGENT, BY CONSTRUCTION. Every create, start,
// stop, rename and removal it makes goes through mutateUpdater, which refuses
// the agent by name and by live identity, refuses any name the agent goes by as
// a destination, and acts on nothing that is not one of this agent's updaters.
// A refusal reaches no mutating engine call at all, so even a bug that hands the
// guard the wrong container cannot stop, rename or replace the data plane.
func TestMutateUpdaterRefusesTheAgent(t *testing.T) {
	ctx := t.Context()
	reference := DockerImageRepository + ":4.1.3"

	refused := func(t *testing.T, engine *fakeDockerEngine, err error) {
		t.Helper()
		if !errors.Is(err, errUpdaterMutationRefused) {
			t.Fatalf("mutateUpdater = %v, want a refusal", err)
		}
		if done := mutations(engine); len(done) != 0 {
			t.Fatalf("a refused mutation reached the engine: %+v", done)
		}
	}

	for _, op := range []string{"start", "stop", "rename", "remove"} {
		for _, address := range []string{"by name", "by ID"} {
			t.Run(op+" the agent "+address, func(t *testing.T) {
				controller, engine, _ := dockerUpdaterFixture(t)
				target := controller.options.TargetName
				if address == "by ID" {
					target = engine.containers[controller.options.TargetName].ID
				}
				_, err := controller.mutateUpdater(ctx, updaterMutation{op: op, target: target, rename: "node-updater-moved", force: true})
				refused(t, engine, err)
			})
		}
	}

	t.Run("a container that is not an updater", func(t *testing.T) {
		controller, engine, updater := dockerUpdaterFixture(t)
		stranger := updater
		stranger.ID, stranger.Name = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "/postgres"
		stranger.Config, _ = json.Marshal(map[string]any{"Image": "postgres:17", "Cmd": []string{"postgres"}})
		engine.containers["postgres"] = stranger
		for _, op := range []string{"start", "stop", "rename", "remove"} {
			_, err := controller.mutateUpdater(ctx, updaterMutation{op: op, target: "postgres", rename: "postgres-old"})
			refused(t, engine, err)
		}
	})

	t.Run("renaming an updater to the agent's name", func(t *testing.T) {
		controller, engine, _ := dockerUpdaterFixture(t)
		_, err := controller.mutateUpdater(ctx, updaterMutation{op: "rename", target: "node-updater", rename: controller.options.TargetName})
		refused(t, engine, err)
	})

	t.Run("creating under the agent's name", func(t *testing.T) {
		controller, engine, updater := dockerUpdaterFixture(t)
		source, _ := successorSource(updater)
		_, err := controller.mutateUpdater(ctx, updaterMutation{op: "create", target: controller.options.TargetName,
			source: source, image: engine.images[reference], reference: reference})
		refused(t, engine, err)
	})

	t.Run("creating a clone of the agent", func(t *testing.T) {
		controller, engine, _ := dockerUpdaterFixture(t)
		_, err := controller.mutateUpdater(ctx, updaterMutation{op: "create", target: "node-updater-next-1a2b3c4d",
			source: engine.containers[controller.options.TargetName], image: engine.images[reference], reference: reference})
		refused(t, engine, err)
	})

	t.Run("creating from an unofficial image", func(t *testing.T) {
		controller, engine, updater := dockerUpdaterFixture(t)
		source, _ := successorSource(updater)
		_, err := controller.mutateUpdater(ctx, updaterMutation{op: "create", target: "node-updater-next-1a2b3c4d",
			source: source, image: engine.images[reference], reference: "docker.io/someone/passwall-node:4.1.3"})
		refused(t, engine, err)
	})

	t.Run("an agent that cannot be identified", func(t *testing.T) {
		controller, engine, _ := dockerUpdaterFixture(t)
		delete(engine.containers, controller.options.TargetName)
		_, err := controller.mutateUpdater(ctx, updaterMutation{op: "stop", target: "node-updater"})
		refused(t, engine, err)
	})

	t.Run("an updater of this agent is acted on by its identity", func(t *testing.T) {
		controller, engine, updater := dockerUpdaterFixture(t)
		source, err := successorSource(updater)
		if err != nil {
			t.Fatal(err)
		}
		id, err := controller.mutateUpdater(ctx, updaterMutation{op: "create", target: "node-updater-next-1a2b3c4d",
			source: source, image: engine.images[reference], reference: reference})
		if err != nil || !validSHA256(id) {
			t.Fatalf("create = (%q, %v)", id, err)
		}
		// Addressed by name, acted on by the identity that was checked: a name
		// that changed hands between the check and the call cannot redirect it.
		if _, err := controller.mutateUpdater(ctx, updaterMutation{op: "start", target: "node-updater-next-1a2b3c4d"}); err != nil {
			t.Fatal(err)
		}
		if _, err := controller.mutateUpdater(ctx, updaterMutation{op: "stop", target: id}); err != nil {
			t.Fatal(err)
		}
		if _, err := controller.mutateUpdater(ctx, updaterMutation{op: "rename", target: id, rename: "node-updater-renamed"}); err != nil {
			t.Fatal(err)
		}
		if _, err := controller.mutateUpdater(ctx, updaterMutation{op: "remove", target: "node-updater-renamed"}); err != nil {
			t.Fatal(err)
		}
		want := []fakeOp{
			{"create", "node-updater-next-1a2b3c4d", ""}, {"start", id, ""}, {"stop", id, ""},
			{"rename", id, "node-updater-renamed"}, {"remove", id, ""},
		}
		got := mutations(engine)
		if len(got) != len(want) {
			t.Fatalf("mutations = %+v, want %+v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("mutations = %+v, want %+v", got, want)
			}
		}
		// A container that is gone is reported as gone, not refused, so a caller
		// can treat a 404 as the success it is.
		if _, err := controller.mutateUpdater(ctx, updaterMutation{op: "remove", target: id}); !errors.Is(err, errDockerNotFound) {
			t.Fatalf("removing a removed container = %v, want a 404", err)
		}
	})
}
