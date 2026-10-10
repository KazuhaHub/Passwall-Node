package process

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
)

type collectionOutput struct{ closed atomic.Bool }

func (*collectionOutput) Write(p []byte) (int, error) { return len(p), nil }
func (w *collectionOutput) Close() error              { w.closed.Store(true); return nil }

type collectionLaunch struct {
	deployment agentcore.Deployment
	output     *collectionOutput
}

func TestCollectionRevisionOwnsProcessOutputAcrossRollback(t *testing.T) {
	launches := make(chan collectionLaunch, 16)
	s := newTestSupervisorWithOptions(t, func(o *Options) {
		o.StartGrace = 1500 * time.Millisecond
		o.StdoutForDeployment = func(d agentcore.Deployment) io.Writer {
			w := &collectionOutput{}
			launches <- collectionLaunch{d, w}
			return w
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() { shutdownSupervisor(t, cancel, done) })
	next := func(revision uint64) collectionLaunch {
		t.Helper()
		select {
		case launch := <-launches:
			if launch.deployment.CollectRevision != revision || launch.deployment.Engine != "test" || launch.deployment.BinaryPath != s.options.Binary || launch.deployment.Version != "test" {
				t.Fatalf("wrong output deployment: %+v", launch.deployment)
			}
			return launch
		case <-time.After(testProcessTimeout):
			t.Fatal("missing deployment output")
			return collectionLaunch{}
		}
	}
	d := agentcore.Deployment{Artifact: testArtifact("valid"), Engine: "test", BinaryPath: s.options.Binary, Version: "test", CollectRevision: 7}
	if err := s.Deploy(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	first := next(7)
	d.CollectRevision = 8
	if err := s.Deploy(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	second := next(8)
	if !first.output.closed.Load() || second.output.closed.Load() {
		t.Fatal("process outputs do not follow process lifetime")
	}
	if err := s.Deploy(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	select {
	case <-launches:
		t.Fatal("unchanged deployment restarted")
	default:
	}
	d.Artifact = testArtifact("crash")
	d.CollectRevision = 9
	if err := s.Deploy(t.Context(), d); err == nil {
		t.Fatal("crashing candidate accepted")
	}
	failed := next(9)
	rollback := next(8)
	if !second.output.closed.Load() || !failed.output.closed.Load() || rollback.output.closed.Load() {
		t.Fatal("candidate/rollback outputs were not closed correctly")
	}
	if s.Status().CollectRevision != 8 {
		t.Fatalf("failed revision became active: %+v", s.Status())
	}
	if err := s.Apply(t.Context(), testArtifact("changed")); err != nil {
		t.Fatal(err)
	}
	next(8)
	if !rollback.output.closed.Load() {
		t.Fatal("Apply did not release previous output")
	}
}

func TestInitialCollectionRevisionUsesConfirmedConfig(t *testing.T) {
	launches := make(chan agentcore.Deployment, 1)
	s := newTestSupervisorWithOptions(t, func(o *Options) {
		o.RequireInitialConfigDigest = true
		o.InitialConfigDigest = testArtifact("valid").Digest
		o.InitialCollectRevision = 7
		o.StdoutForDeployment = func(d agentcore.Deployment) io.Writer { launches <- d; return io.Discard }
	})
	if err := os.WriteFile(filepath.Join(s.options.StateDir, currentConfigName), []byte("valid"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() { shutdownSupervisor(t, cancel, done) })
	select {
	case d := <-launches:
		if d.CollectRevision != 7 || d.Artifact.Digest != s.options.InitialConfigDigest {
			t.Fatalf("wrong startup deployment: %+v", d)
		}
	case <-time.After(testProcessTimeout):
		t.Fatal("confirmed config did not start")
	}
}

func TestOutputFactoryCannotFallBackToRawOutput(t *testing.T) {
	s := newTestSupervisorWithOptions(t, func(o *Options) { o.StdoutForDeployment = func(agentcore.Deployment) io.Writer { return nil } })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() { shutdownSupervisor(t, cancel, done) })
	d := agentcore.Deployment{Artifact: testArtifact("valid"), Engine: "test", BinaryPath: s.options.Binary, Version: "test", CollectRevision: 7}
	if err := s.Deploy(t.Context(), d); err == nil {
		t.Fatal("missing private output started with raw stdout")
	}
}
