package protocol

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestTaskExpiryIsSeparateImmutableIdentityFromV1InputDigest(t *testing.T) {
	task := Task{ID: "task-expiry-wire", Kind: "test.v1", Args: []byte("same input")}
	task.InputSHA256 = ComputeTaskInputSHA256(task.Kind, task.Args)
	legacy, err := json.Marshal(task)
	if err != nil || strings.Contains(string(legacy), "not_after_ms") {
		t.Fatalf("legacy wire changed: %s err=%v", legacy, err)
	}
	for _, deadline := range []int64{1, 1000, math.MaxInt64} {
		task.NotAfterMS = deadline
		if err := ValidateTasks([]Task{task}); err != nil {
			t.Fatal(err)
		}
		if task.InputSHA256 != ComputeTaskInputSHA256(task.Kind, task.Args) {
			t.Fatal("additive deadline changed the published v1 input digest")
		}
		payload, err := json.Marshal(task)
		if err != nil || !strings.Contains(string(payload), "not_after_ms") {
			t.Fatalf("deadline not serialized: %s err=%v", payload, err)
		}
		var roundtrip Task
		if err := json.Unmarshal(payload, &roundtrip); err != nil || roundtrip.NotAfterMS != deadline {
			t.Fatalf("deadline lost on roundtrip: %+v err=%v", roundtrip, err)
		}
		result := TaskResult{ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256, NotAfterMS: deadline, OK: true}
		if err := ValidateTaskResults([]TaskResult{result}); err != nil {
			t.Fatal(err)
		}
	}
	task.NotAfterMS = -1
	if err := ValidateTasks([]Task{task}); err == nil {
		t.Fatal("negative start deadline accepted")
	}
	result := TaskResult{ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256, NotAfterMS: -1, OK: true}
	if err := ValidateTaskResults([]TaskResult{result}); err == nil {
		t.Fatal("negative echoed deadline accepted")
	}
}

func TestTaskExpiryCapabilityIsNotAnExecutableKind(t *testing.T) {
	task := Task{ID: "task-reserved-expiry", Kind: strings.TrimPrefix(CapabilityTaskExpiryV1, "task.")}
	task.InputSHA256 = ComputeTaskInputSHA256(task.Kind, nil)
	if err := ValidateTasks([]Task{task}); err == nil {
		t.Fatal("expiry infrastructure advertised as a task handler")
	}
	if err := ValidateTaskResults([]TaskResult{{ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256, OK: true}}); err == nil {
		t.Fatal("reserved expiry infrastructure accepted as a task outcome")
	}
}
