package protocol

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// ValidateNodeReport validates the untrusted half of the sync wire contract.
// It lives with the protocol types so every PSP transport applies the same
// rules and a future agent implementation can self-check before sending.
func ValidateNodeReport(report NodeReport) error {
	if report.AgentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	if report.ProtocolVersion < 0 || report.ProtocolVersion > ProtocolVersion1 {
		return fmt.Errorf("protocol_version %d is unsupported", report.ProtocolVersion)
	}
	if report.ReportedAtMS < 0 {
		return fmt.Errorf("reported_at_ms must be non-negative")
	}
	if report.CoreEngine != "" && report.CoreEngine != "xray" && report.CoreEngine != "sing-box" {
		return fmt.Errorf("core_engine %q is unsupported", report.CoreEngine)
	}
	if err := validateCapabilities(report.Capabilities); err != nil {
		return err
	}
	for _, stream := range []string{StreamConfig, StreamRoster, StreamDirectives} {
		state, ok := report.Have[stream]
		if !ok {
			return fmt.Errorf("have.%s is required", stream)
		}
		if err := validateStreamState(stream, state); err != nil {
			return err
		}
	}
	for stream := range report.Have {
		if !validStream(stream) {
			return fmt.Errorf("have contains unknown stream %q", stream)
		}
	}
	if report.Partial {
		if len(report.Objects) != 0 || len(report.ListenerCounters) != 0 ||
			len(report.Clients) != 0 || len(report.Subjects) != 0 {
			return fmt.Errorf("partial report must omit full enumerations")
		}
		return validateOutbox(report)
	}

	seenObjects := make(map[string]struct{}, len(report.Objects))
	for _, status := range report.Objects {
		if err := validateReportedObject(status); err != nil {
			return err
		}
		identity := status.Stream + "\x00" + status.Key
		if _, exists := seenObjects[identity]; exists {
			return fmt.Errorf("duplicate %s object %q", status.Stream, status.Key)
		}
		seenObjects[identity] = struct{}{}
	}
	seenListeners := make(map[ListenerKey]struct{}, len(report.ListenerCounters))
	for _, counter := range report.ListenerCounters {
		if _, err := counter.Key.RowID(); err != nil {
			return err
		}
		if counter.UpBytes < 0 || counter.DownBytes < 0 {
			return fmt.Errorf("listener %s has negative counters", counter.Key)
		}
		if _, exists := seenListeners[counter.Key]; exists {
			return fmt.Errorf("duplicate listener counter %q", counter.Key)
		}
		seenListeners[counter.Key] = struct{}{}
	}
	seenClients := make(map[ClientKey]struct{}, len(report.Clients))
	for _, counter := range report.Clients {
		if _, err := counter.Key.RowID(); err != nil {
			return err
		}
		if counter.UpBytes < 0 || counter.DownBytes < 0 {
			return fmt.Errorf("client %s has negative counters", counter.Key)
		}
		switch counter.Gate {
		case GateUnconfigured, GateArmed, GateClosed:
		default:
			return fmt.Errorf("client %s has invalid gate %q", counter.Key, counter.Gate)
		}
		seenIPs := make(map[netip.Addr]struct{}, len(counter.LiveIPs))
		for _, raw := range counter.LiveIPs {
			addr, err := netip.ParseAddr(raw)
			if err != nil || addr.String() != raw {
				return fmt.Errorf("client %s has non-canonical live IP %q", counter.Key, raw)
			}
			if _, exists := seenIPs[addr]; exists {
				return fmt.Errorf("client %s repeats live IP %q", counter.Key, raw)
			}
			seenIPs[addr] = struct{}{}
		}
		if _, exists := seenClients[counter.Key]; exists {
			return fmt.Errorf("duplicate client counter %q", counter.Key)
		}
		seenClients[counter.Key] = struct{}{}
	}
	seenSubjects := make(map[SubjectKey]struct{}, len(report.Subjects))
	for _, subject := range report.Subjects {
		if _, err := subject.Subject.RowID(); err != nil {
			return err
		}
		if subject.IPLocalCount < 0 || subject.IPWouldDenySinceLastReport < 0 {
			return fmt.Errorf("subject %s has negative observations", subject.Subject)
		}
		if _, exists := seenSubjects[subject.Subject]; exists {
			return fmt.Errorf("duplicate subject observation %q", subject.Subject)
		}
		seenSubjects[subject.Subject] = struct{}{}
	}
	return validateOutbox(report)
}

func validateStreamState(stream string, state StreamState) error {
	if state.ETag == "" {
		if !state.Applied.Zero() {
			return fmt.Errorf("have.%s has an applied version without an etag", stream)
		}
		return nil
	}
	decoded, err := hex.DecodeString(string(state.ETag))
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("have.%s etag must be a lowercase sha256 hex digest", stream)
	}
	if hex.EncodeToString(decoded) != string(state.ETag) {
		return fmt.Errorf("have.%s etag must be lowercase", stream)
	}
	if !state.Applied.Committed() {
		return fmt.Errorf("have.%s has an etag without an applied version", stream)
	}
	return nil
}

func validateReportedObject(status ObjectStatus) error {
	switch status.Stream {
	case StreamConfig:
		if _, err := ListenerKey(status.Key).RowID(); err != nil {
			return err
		}
	case StreamRoster:
		if _, err := ClientKey(status.Key).RowID(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("object %q has invalid stream %q", status.Key, status.Stream)
	}
	if !status.SinceVersion.Committed() {
		return fmt.Errorf("%s object %s has zero since_version", status.Stream, status.Key)
	}
	if status.FirstFailedAtMS < 0 {
		return fmt.Errorf("object %s has a negative failure timestamp", status.Key)
	}
	if !utf8.ValidString(status.IssueCode) || len(status.IssueCode) > MaxIssueCodeBytes {
		return fmt.Errorf("object %s has an invalid or oversized issue code", status.Key)
	}
	if status.BlockedOn != "" {
		if !utf8.ValidString(status.BlockedOn) || len(status.BlockedOn) > MaxIssueKeyBytes {
			return fmt.Errorf("object %s has an invalid or oversized blocked_on", status.Key)
		}
		if _, err := ListenerKey(status.BlockedOn).RowID(); err != nil {
			return fmt.Errorf("object %s blocked_on: %w", status.Key, err)
		}
	}
	switch status.State {
	case ObjectApplied:
		if status.FirstFailedAtMS != 0 || status.IssueCode != "" || status.BlockedOn != "" {
			return fmt.Errorf("applied object %s retains failure metadata", status.Key)
		}
	case ObjectPending:
		if status.FirstFailedAtMS == 0 || status.IssueCode != "" || status.BlockedOn != "" {
			return fmt.Errorf("pending object %s requires a start time only", status.Key)
		}
	case ObjectRejected:
		if status.FirstFailedAtMS == 0 || status.IssueCode == "" || status.BlockedOn != "" {
			return fmt.Errorf("rejected object %s requires a start time and issue code", status.Key)
		}
	case ObjectBlocked:
		if status.FirstFailedAtMS == 0 || status.IssueCode != "" || status.BlockedOn == "" {
			return fmt.Errorf("blocked object %s requires a start time and blocked_on", status.Key)
		}
	default:
		return fmt.Errorf("object %s has invalid state %q", status.Key, status.State)
	}
	return nil
}

func validateOutbox(report NodeReport) error {
	if len(report.Issues) > MaxIssuesPerReport {
		return fmt.Errorf("issues exceeds maximum of %d", MaxIssuesPerReport)
	}
	seenIssues := make(map[[3]string]struct{}, len(report.Issues))
	for _, issue := range report.Issues {
		if issue.Code == "" {
			return fmt.Errorf("issue code is required")
		}
		if !utf8.ValidString(issue.Code) || !utf8.ValidString(issue.Key) || !utf8.ValidString(issue.Detail) ||
			len(issue.Code) > MaxIssueCodeBytes || len(issue.Key) > MaxIssueKeyBytes || len(issue.Detail) > MaxIssueDetailBytes {
			return fmt.Errorf("issue %q exceeds field size limits", issue.Code)
		}
		identity := [3]string{issue.Code, issue.Key, issue.Detail}
		if _, exists := seenIssues[identity]; exists {
			return fmt.Errorf("duplicate issue %q for key %q", issue.Code, issue.Key)
		}
		seenIssues[identity] = struct{}{}
	}
	for _, result := range report.TaskResults {
		if result.Kind != "" || result.InputSHA256 != "" || result.ErrorCode != "" || result.Indeterminate {
			return ValidateTaskResults(report.TaskResults)
		}
	}
	return validateLegacyTaskResults(report.TaskResults)
}

// ValidateTasks validates task identity, bounds, and content binding. It does
// not reject an unknown but canonical kind; capability negotiation happens at
// PSP and an accidental unknown dispatch becomes an explicit failed result at
// the worker rather than a malformed round trip.
func ValidateTasks(tasks []Task) error {
	if len(tasks) > MaxTasksPerResponse {
		return fmt.Errorf("tasks exceeds maximum of %d", MaxTasksPerResponse)
	}
	seen := make(map[string]struct{}, len(tasks))
	totalArgs := 0
	for _, task := range tasks {
		if !validTaskID(task.ID) || len(task.ID) > MaxTaskIDBytes {
			return fmt.Errorf("task id must be 1..%d canonical lowercase ASCII characters", MaxTaskIDBytes)
		}
		if !validToken(task.Kind) || len(task.Kind) > MaxTaskKindBytes {
			return fmt.Errorf("task %q kind must be 1..%d canonical lowercase characters", task.ID, MaxTaskKindBytes)
		}
		if TaskCapability(task.Kind) == CapabilityTaskExecutionV1 {
			return fmt.Errorf("task %q kind %q is reserved by the execution capability", task.ID, task.Kind)
		}
		if len(task.Args) > MaxTaskArgsBytes {
			return fmt.Errorf("task %q args exceeds maximum of %d bytes", task.ID, MaxTaskArgsBytes)
		}
		if len(task.Args) > MaxTaskArgsBytesPerResponse-totalArgs {
			return fmt.Errorf("task args exceed aggregate maximum of %d bytes", MaxTaskArgsBytesPerResponse)
		}
		totalArgs += len(task.Args)
		if err := validateDigest(task.InputSHA256); err != nil {
			return fmt.Errorf("task %q input_sha256: %w", task.ID, err)
		}
		if want := ComputeTaskInputSHA256(task.Kind, task.Args); task.InputSHA256 != want {
			return fmt.Errorf("task %q input_sha256 does not match kind and args", task.ID)
		}
		if _, exists := seen[task.ID]; exists {
			return fmt.Errorf("duplicate task %q", task.ID)
		}
		seen[task.ID] = struct{}{}
	}
	return nil
}

// ValidateTaskResults validates immutable task-result payloads before they are
// persisted or sent. Failed results require a stable machine code and a
// bounded human diagnostic; successful results carry neither.
func ValidateTaskResults(results []TaskResult) error {
	if len(results) > MaxTaskResultsPerReport {
		return fmt.Errorf("task_results exceeds maximum of %d", MaxTaskResultsPerReport)
	}
	seen := make(map[string]struct{}, len(results))
	totalResult := 0
	for _, result := range results {
		if !validTaskID(result.ID) || len(result.ID) > MaxTaskIDBytes {
			return fmt.Errorf("task result id must be 1..%d canonical lowercase ASCII characters", MaxTaskIDBytes)
		}
		if !validToken(result.Kind) || len(result.Kind) > MaxTaskKindBytes {
			return fmt.Errorf("task result %q kind must be canonical and bounded", result.ID)
		}
		if TaskCapability(result.Kind) == CapabilityTaskExecutionV1 {
			return fmt.Errorf("task result %q kind %q is reserved by the execution capability", result.ID, result.Kind)
		}
		if err := validateDigest(result.InputSHA256); err != nil {
			return fmt.Errorf("task result %q input_sha256: %w", result.ID, err)
		}
		if len(result.Result) > MaxTaskResultBytes {
			return fmt.Errorf("task result %q payload exceeds maximum of %d bytes", result.ID, MaxTaskResultBytes)
		}
		if len(result.Result) > MaxTaskResultBytesPerReport-totalResult {
			return fmt.Errorf("task result payloads exceed aggregate maximum of %d bytes", MaxTaskResultBytesPerReport)
		}
		totalResult += len(result.Result)
		if !utf8.ValidString(result.Error) || len(result.Error) > MaxTaskErrorBytes {
			return fmt.Errorf("task result %q error is invalid or oversized", result.ID)
		}
		if result.OK {
			if result.Indeterminate || result.ErrorCode != "" || result.Error != "" {
				return fmt.Errorf("successful task result %q cannot carry an error", result.ID)
			}
		} else {
			if !validToken(result.ErrorCode) || len(result.ErrorCode) > MaxTaskErrorCodeBytes {
				return fmt.Errorf("failed task result %q requires a canonical bounded error_code", result.ID)
			}
			if strings.TrimSpace(result.Error) == "" || strings.TrimSpace(result.Error) != result.Error {
				return fmt.Errorf("failed task result %q requires a canonical error", result.ID)
			}
			if len(result.Result) != 0 {
				return fmt.Errorf("failed task result %q cannot carry a result payload", result.ID)
			}
		}
		if _, exists := seen[result.ID]; exists {
			return fmt.Errorf("duplicate task result %q", result.ID)
		}
		seen[result.ID] = struct{}{}
	}
	return nil
}

func validateLegacyTaskResults(results []TaskResult) error {
	if len(results) > MaxTaskResultsPerReport {
		return fmt.Errorf("task_results exceeds maximum of %d", MaxTaskResultsPerReport)
	}
	seen := make(map[string]struct{}, len(results))
	totalResult := 0
	for _, result := range results {
		if result.Kind != "" || result.InputSHA256 != "" || result.ErrorCode != "" || result.Indeterminate {
			return fmt.Errorf("task result %q mixes durable and legacy result schemas", result.ID)
		}
		if !validTaskID(result.ID) || len(result.ID) > MaxTaskIDBytes {
			return fmt.Errorf("legacy task result id must be canonical and bounded")
		}
		if len(result.Result) > MaxTaskResultBytes || len(result.Result) > MaxTaskResultBytesPerReport-totalResult {
			return fmt.Errorf("legacy task result %q exceeds result size limits", result.ID)
		}
		totalResult += len(result.Result)
		if !utf8.ValidString(result.Error) || len(result.Error) > MaxTaskErrorBytes {
			return fmt.Errorf("legacy task result %q error is invalid or oversized", result.ID)
		}
		if result.OK && result.Error != "" {
			return fmt.Errorf("successful legacy task result %q cannot carry an error", result.ID)
		}
		if !result.OK && (strings.TrimSpace(result.Error) == "" || strings.TrimSpace(result.Error) != result.Error) {
			return fmt.Errorf("failed legacy task result %q requires a canonical error", result.ID)
		}
		if _, exists := seen[result.ID]; exists {
			return fmt.Errorf("duplicate task result %q", result.ID)
		}
		seen[result.ID] = struct{}{}
	}
	return nil
}

func validateCapabilities(capabilities []string) error {
	if len(capabilities) > MaxCapabilitiesPerReport {
		return fmt.Errorf("capabilities exceeds maximum of %d", MaxCapabilitiesPerReport)
	}
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if !validToken(capability) || len(capability) > MaxCapabilityBytes {
			return fmt.Errorf("capability must be 1..%d canonical lowercase characters", MaxCapabilityBytes)
		}
		if _, exists := seen[capability]; exists {
			return fmt.Errorf("duplicate capability %q", capability)
		}
		seen[capability] = struct{}{}
	}
	return nil
}

func validateDigest(value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256DigestBytes || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("must be a lowercase sha256 hex digest")
	}
	return nil
}

const sha256DigestBytes = 32

func validTaskID(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if asciiLowerAlphaNumeric(character) {
			continue
		}
		if index > 0 && (character == '_' || character == '-' || character == '.' || character == ':') {
			continue
		}
		return false
	}
	return true
}

func validToken(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func asciiLowerAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func validStream(stream string) bool {
	return stream == StreamConfig || stream == StreamRoster || stream == StreamDirectives
}
