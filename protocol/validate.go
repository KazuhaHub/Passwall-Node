package protocol

import (
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// ValidateNodeReportBase validates the control half of the sync wire contract —
// everything that decides config, roster, directives, accounting and quota.
//
// IT IS SPLIT FROM THE HOST SUBTREE ON PURPOSE. Host telemetry is best-effort
// observation, and a panel that ran one validator over the whole report would
// let a malformed telemetry field reject the round trip, which is exactly the
// coupling the feature is forbidden to introduce. The panel validates this
// first, keeps the control response regardless of what it finds in Host, and
// validates Host separately.
func ValidateNodeReportBase(report NodeReport) error {
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

// ValidateNodeReport is the full check a SENDER runs before putting a report on
// the wire.
//
// The panel deliberately does NOT use this. It runs ValidateNodeReportBase, then
// ValidateHostObservation in isolation, so a malformed telemetry field cannot
// cost a node its roster. A sender is the mirror image: it wants one answer
// before transmitting, and it has no isolation problem to solve because the
// only party it could harm is itself.
func ValidateNodeReport(report NodeReport) error {
	if err := ValidateNodeReportBase(report); err != nil {
		return err
	}
	if report.Host == nil {
		// Declaring the capability and carrying no sample is legal — that is
		// what the cadence produces on most rounds.
		return nil
	}
	// A host sample WITHOUT the capability is not version skew. It is a build
	// that registered no collector and reported anyway, or a producer bug.
	// Accepting it would demote the capability to advisory and retire the one
	// signal that lets the panel tell "older node" from "node that stopped
	// collecting".
	if !hasCapability(report.Capabilities, CapabilityHostTelemetry) {
		return fmt.Errorf("host observation without %s capability", CapabilityHostTelemetry)
	}
	if err := ValidateHostObservation(*report.Host); err != nil {
		return fmt.Errorf("host: %w", err)
	}
	return nil
}

func hasCapability(capabilities []string, want string) bool {
	for _, capability := range capabilities {
		if capability == want {
			return true
		}
	}
	return false
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
		if TaskCapability(task.Kind) == CapabilityTaskExecutionV1 || TaskCapability(task.Kind) == CapabilityTaskExpiryV1 {
			return fmt.Errorf("task %q kind %q is reserved by the execution capability", task.ID, task.Kind)
		}
		if task.NotAfterMS < 0 {
			return fmt.Errorf("task %q not_after_ms must be non-negative", task.ID)
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
		if TaskCapability(result.Kind) == CapabilityTaskExecutionV1 || TaskCapability(result.Kind) == CapabilityTaskExpiryV1 {
			return fmt.Errorf("task result %q kind %q is reserved by the execution capability", result.ID, result.Kind)
		}
		if result.NotAfterMS < 0 {
			return fmt.Errorf("task result %q not_after_ms must be non-negative", result.ID)
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
		if result.Kind != "" || result.InputSHA256 != "" || result.NotAfterMS != 0 || result.ErrorCode != "" || result.Indeterminate {
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

// maxUnixMilli is 9999-12-31T23:59:59.999Z. Every non-zero millisecond field in
// a host sample must land at or below it, so a wild value cannot reach a
// TIMESTAMP column that one of the three dialects will reject or, worse,
// silently reinterpret.
const maxUnixMilli = int64(253402300799999)

// ValidateHostObservation validates one untrusted telemetry sample.
//
// THE ORDER IS NOT COSMETIC. Every fixed bound — array counts, string lengths,
// numeric ranges — is checked before a single map is allocated or a slice is
// sorted. The input is attacker-controlled JSON from an authenticated but
// untrusted peer, and a validator that allocates first can be made to allocate
// on a sample it was always going to reject.
//
// PRESENCE IS NOT OPTIONALITY, AND ABSENCE IS NOT ZERO. Every field that a host
// may legitimately fail to provide is a pointer, and a pointer that IS present
// must hold a value the panel can divide, compare or display. A metric the agent
// could not read must arrive as an Unavailable token; it must never arrive as a
// healthy-looking zero. That rule is what the feature's honesty rests on, so it
// is enforced here rather than left to each consumer.
func ValidateHostObservation(host HostObservation) error {
	if err := validateHostIdentity(host); err != nil {
		return err
	}
	if err := validateHostScope(host.Scope); err != nil {
		return err
	}
	if err := validateHostPlatform(host.Platform); err != nil {
		return err
	}
	if err := validateUnavailable(host.Unavailable); err != nil {
		return err
	}
	if host.CPU != nil {
		if err := validateCPUObservation(*host.CPU); err != nil {
			return err
		}
	}
	if host.Load != nil {
		if err := validateLoadObservation(*host.Load); err != nil {
			return err
		}
	}
	if host.Memory != nil {
		if err := validateMemoryObservation(*host.Memory); err != nil {
			return err
		}
	}
	if host.Filesystem != nil {
		if err := validateFilesystemObservation(*host.Filesystem); err != nil {
			return err
		}
	}
	if host.Network != nil {
		if err := validateNetworkObservation(*host.Network); err != nil {
			return err
		}
	}
	if host.TCP != nil {
		if err := validateTCPObservation(*host.TCP); err != nil {
			return err
		}
	}
	if host.Sockets != nil {
		if err := validateSocketObservation(*host.Sockets); err != nil {
			return err
		}
	}
	if host.Processes != nil {
		if err := validateProcessObservation(*host.Processes); err != nil {
			return err
		}
	}
	if host.Runtime != nil {
		if err := validateRuntimeObservation(*host.Runtime); err != nil {
			return err
		}
	}
	if host.Tuning != nil {
		if err := validateTuningObservation(*host.Tuning); err != nil {
			return err
		}
	}
	return nil
}

func validateHostIdentity(host HostObservation) error {
	if !validSampleID(host.SampleID) {
		return fmt.Errorf("sample_id must be exactly %d lowercase hex characters", SampleIDBytes)
	}
	if host.CollectedAtMS <= 0 || host.CollectedAtMS > maxUnixMilli {
		return fmt.Errorf("collected_at_ms must be a positive unix millisecond timestamp")
	}
	if host.UptimeMS < 0 {
		return fmt.Errorf("uptime_ms must be non-negative")
	}
	return validateText("boot_id", host.BootID, MaxBootIDBytes, false)
}

func validateHostScope(scope HostScope) error {
	if err := validateEnum("scope.deployment", string(scope.Deployment),
		string(DeploymentSystemd), string(DeploymentDocker), string(DeploymentManual), string(DeploymentUnknown)); err != nil {
		return err
	}
	if err := validateEnum("scope.resource_scope", string(scope.ResourceScope),
		string(ScopeHost), string(ScopeContainer), string(ScopeMixed), string(ScopeUnknown)); err != nil {
		return err
	}
	switch scope.CgroupVersion {
	case 0, 1, 2:
	default:
		return fmt.Errorf("scope.cgroup_version %d is unsupported", scope.CgroupVersion)
	}
	return validateEnum("scope.data_filesystem_scope", string(scope.DataFilesystemScope),
		string(FilesystemScopeHostMount), string(FilesystemScopeContainerMount), string(FilesystemScopeUnknown))
}

func validateHostPlatform(platform PlatformObservation) error {
	if err := validateText("platform.os", platform.OS, MaxPlatformFieldBytes, true); err != nil {
		return err
	}
	if err := validateText("platform.arch", platform.Arch, MaxPlatformFieldBytes, true); err != nil {
		return err
	}
	if err := validateText("platform.distribution_id", platform.DistributionID, MaxPlatformFieldBytes, false); err != nil {
		return err
	}
	if err := validateText("platform.version_id", platform.VersionID, MaxKernelReleaseBytes, false); err != nil {
		return err
	}
	if err := validateText("platform.kernel_release", platform.KernelRelease, MaxKernelReleaseBytes, false); err != nil {
		return err
	}
	if platform.LogicalCPUs < MinLogicalCPUs || platform.LogicalCPUs > MaxLogicalCPUs {
		return fmt.Errorf("platform.logical_cpus must be between %d and %d", MinLogicalCPUs, MaxLogicalCPUs)
	}
	return nil
}

// validateUnavailable checks the tokens BEFORE deduplicating them: the bound is
// a fixed limit on an untrusted array, and the set that deduplicates it is
// allocated only once the input is known to be small enough to be worth
// allocating for.
func validateUnavailable(unavailable []string) error {
	if len(unavailable) > MaxUnavailableTokens {
		return fmt.Errorf("unavailable holds %d tokens, at most %d are allowed", len(unavailable), MaxUnavailableTokens)
	}
	for _, token := range unavailable {
		// Unknown tokens are LEGAL and must stay legal: a newer agent that
		// learns one more section must not be rejected by a panel that predates
		// it. What is enforced is the shape, so a token can never become an
		// error string, a host path or an unbounded index value.
		if len(token) > MaxUnavailableTokenBytes {
			return fmt.Errorf("unavailable token %q exceeds %d bytes", token, MaxUnavailableTokenBytes)
		}
		if !validToken(token) {
			return fmt.Errorf("unavailable token %q is not a canonical token", token)
		}
	}
	seen := make(map[string]struct{}, len(unavailable))
	for _, token := range unavailable {
		if _, exists := seen[token]; exists {
			return fmt.Errorf("unavailable repeats token %q", token)
		}
		seen[token] = struct{}{}
	}
	return nil
}

func validateCPUObservation(cpu CPUObservation) error {
	if cpu.System == nil && cpu.Cgroup == nil {
		return fmt.Errorf("cpu must carry system, cgroup, or both")
	}
	if system := cpu.System; system != nil {
		if err := validateText("cpu.system.counter_epoch", system.CounterEpoch, MaxCounterEpochBytes, true); err != nil {
			return err
		}
		for _, field := range []struct {
			name  string
			value uint64
		}{
			{"cpu.system.total", system.Total},
			{"cpu.system.idle", system.Idle},
			{"cpu.system.iowait", system.IOWait},
			{"cpu.system.steal", system.Steal},
		} {
			if err := withinInt64(field.name, field.value); err != nil {
				return err
			}
		}
		// Idle and iowait are both subsets of total. Exceeding it means the four
		// fields did not come from one /proc/stat read, and a difference taken
		// across such a sample would be nonsense rather than merely imprecise —
		// so the sample is rejected instead of absorbed.
		if system.Idle+system.IOWait > system.Total {
			return fmt.Errorf("cpu.system idle + iowait exceeds total")
		}
	}
	if cgroup := cpu.Cgroup; cgroup != nil {
		if err := validateCgroupCPU(*cgroup); err != nil {
			return err
		}
	}
	return nil
}

func validateCgroupCPU(cgroup CgroupCPUObservation) error {
	hasUsage := cgroup.UsageUS != nil
	hasQuota := cgroup.QuotaUS != nil || cgroup.PeriodUS != nil
	hasEffectiveCPUs := cgroup.EffectiveCPUs != nil
	throttleFields := 0
	for _, value := range []*uint64{cgroup.NrPeriods, cgroup.NrThrottled, cgroup.ThrottledUS} {
		if value != nil {
			throttleFields++
		}
	}
	// A cgroup section that states nothing at all is worse than no section: it
	// claims container scope and then leaves every field empty, which the panel
	// would render as a container with no measurable limits.
	if !hasUsage && !hasQuota && !hasEffectiveCPUs && throttleFields == 0 {
		return fmt.Errorf("cpu.cgroup must carry usage, quota/period, effective CPUs, or throttle counters")
	}
	// Usage and throttle are cumulative, so they are only meaningful against
	// another sample of the same epoch. Without one the panel would difference
	// across a container restart and report the whole lifetime as one interval.
	if (hasUsage || throttleFields > 0) && cgroup.CounterEpoch == "" {
		return fmt.Errorf("cpu.cgroup.counter_epoch is required with usage or throttle counters")
	}
	if err := validateText("cpu.cgroup.counter_epoch", cgroup.CounterEpoch, MaxCounterEpochBytes, false); err != nil {
		return err
	}
	// Unlimited is expressed by BOTH being absent — see CgroupCPUObservation.
	// One without the other is a malformed report, not a partial limit.
	if (cgroup.QuotaUS == nil) != (cgroup.PeriodUS == nil) {
		return fmt.Errorf("cpu.cgroup quota_us and period_us must be present together")
	}
	if cgroup.QuotaUS != nil && (*cgroup.QuotaUS == 0 || *cgroup.PeriodUS == 0) {
		return fmt.Errorf("cpu.cgroup quota_us and period_us must be greater than zero")
	}
	if throttleFields != 0 && throttleFields != 3 {
		return fmt.Errorf("cpu.cgroup nr_periods, nr_throttled and throttled_us must be present together")
	}
	if cgroup.NrPeriods != nil && *cgroup.NrThrottled > *cgroup.NrPeriods {
		return fmt.Errorf("cpu.cgroup nr_throttled exceeds nr_periods")
	}
	for _, field := range []struct {
		name  string
		value *uint64
	}{
		{"cpu.cgroup.usage_us", cgroup.UsageUS},
		{"cpu.cgroup.user_us", cgroup.UserUS},
		{"cpu.cgroup.system_us", cgroup.SystemUS},
		{"cpu.cgroup.nr_periods", cgroup.NrPeriods},
		{"cpu.cgroup.nr_throttled", cgroup.NrThrottled},
		{"cpu.cgroup.throttled_us", cgroup.ThrottledUS},
		{"cpu.cgroup.quota_us", cgroup.QuotaUS},
		{"cpu.cgroup.period_us", cgroup.PeriodUS},
		{"cpu.cgroup.effective_cpus", cgroup.EffectiveCPUs},
	} {
		if field.value == nil {
			continue
		}
		if err := withinInt64(field.name, *field.value); err != nil {
			return err
		}
	}
	return nil
}

func validateLoadObservation(load LoadObservation) error {
	for _, field := range []struct {
		name  string
		value float64
	}{
		{"load_1", load.Load1},
		{"load_5", load.Load5},
		{"load_15", load.Load15},
	} {
		if err := validMetricFloat(field.name, field.value); err != nil {
			return err
		}
	}
	return nil
}

func validateMemoryObservation(memory MemoryObservation) error {
	if memory.System == nil && memory.Cgroup == nil {
		return fmt.Errorf("memory must carry system, cgroup, or both")
	}
	if system := memory.System; system != nil {
		if err := withinInt64("memory.system.total_bytes", system.TotalBytes); err != nil {
			return err
		}
		if err := withinInt64("memory.system.swap_total_bytes", system.SwapTotalBytes); err != nil {
			return err
		}
		if err := withinInt64("memory.system.swap_free_bytes", system.SwapFreeBytes); err != nil {
			return err
		}
		if system.AvailableBytes != nil {
			if err := withinInt64("memory.system.available_bytes", *system.AvailableBytes); err != nil {
				return err
			}
			if *system.AvailableBytes > system.TotalBytes {
				return fmt.Errorf("memory.system.available_bytes exceeds total_bytes")
			}
		}
		if system.SwapFreeBytes > system.SwapTotalBytes {
			return fmt.Errorf("memory.system.swap_free_bytes exceeds swap_total_bytes")
		}
	}
	cgroup := memory.Cgroup
	if cgroup == nil {
		return nil
	}
	if err := validateText("memory.cgroup.counter_epoch", cgroup.CounterEpoch, MaxCounterEpochBytes, true); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value *uint64
	}{
		{"memory.cgroup.current_bytes", &cgroup.CurrentBytes},
		{"memory.cgroup.limit_bytes", cgroup.LimitBytes},
		{"memory.cgroup.swap_current_bytes", cgroup.SwapCurrentBytes},
		{"memory.cgroup.swap_limit_bytes", cgroup.SwapLimitBytes},
		{"memory.cgroup.oom_events", cgroup.OOMEvents},
		{"memory.cgroup.oom_kill_events", cgroup.OOMKillEvents},
	} {
		if field.value == nil {
			continue
		}
		if err := withinInt64(field.name, *field.value); err != nil {
			return err
		}
	}
	// A limit of zero is reserved: unlimited is expressed by absence. Letting
	// zero through would hand the panel a division whose result is undefined
	// and, worse, a container that reads as permanently at 100% of nothing.
	if cgroup.LimitBytes != nil && *cgroup.LimitBytes == 0 {
		return fmt.Errorf("memory.cgroup.limit_bytes must be absent for unlimited, never zero")
	}
	// current > limit is NOT rejected: a sample taken mid-charge legitimately
	// exceeds the limit, and rejecting the whole report for a race would drop
	// the telemetry of a node that is doing the most interesting thing it ever
	// does. The panel keeps the raw ratio and clamps only when drawing.
	if (cgroup.OOMEvents == nil) != (cgroup.OOMKillEvents == nil) {
		return fmt.Errorf("memory.cgroup oom_events and oom_kill_events must be present together")
	}
	return nil
}

func validateFilesystemObservation(filesystem FilesystemObservation) error {
	if err := withinInt64("filesystem.total_bytes", filesystem.TotalBytes); err != nil {
		return err
	}
	if err := withinInt64("filesystem.available_bytes", filesystem.AvailableBytes); err != nil {
		return err
	}
	if filesystem.AvailableBytes > filesystem.TotalBytes {
		return fmt.Errorf("filesystem.available_bytes exceeds total_bytes")
	}
	// Inodes are paired: a filesystem either reports both or neither. One alone
	// cannot produce a percentage, and a zero would render as "0 of 0 used",
	// which reads as healthy on a filesystem that is in fact out of inodes.
	if (filesystem.TotalInodes == nil) != (filesystem.AvailableInodes == nil) {
		return fmt.Errorf("filesystem total_inodes and available_inodes must be present together")
	}
	if filesystem.TotalInodes != nil {
		if err := withinInt64("filesystem.total_inodes", *filesystem.TotalInodes); err != nil {
			return err
		}
		if err := withinInt64("filesystem.available_inodes", *filesystem.AvailableInodes); err != nil {
			return err
		}
		if *filesystem.AvailableInodes > *filesystem.TotalInodes {
			return fmt.Errorf("filesystem.available_inodes exceeds total_inodes")
		}
	}
	return nil
}

func validateNetworkObservation(network NetworkObservation) error {
	if err := validateText("network.counter_epoch", network.CounterEpoch, MaxCounterEpochBytes, true); err != nil {
		return err
	}
	if err := validateText("network.default_ipv4_interface", network.DefaultIPv4Interface, MaxInterfaceNameBytes, false); err != nil {
		return err
	}
	if err := validateText("network.default_ipv6_interface", network.DefaultIPv6Interface, MaxInterfaceNameBytes, false); err != nil {
		return err
	}
	if len(network.Interfaces) > MaxNetworkInterfaces {
		return fmt.Errorf("network holds %d interfaces, at most %d are allowed", len(network.Interfaces), MaxNetworkInterfaces)
	}
	for _, networkInterface := range network.Interfaces {
		if err := validateNetworkInterface(networkInterface); err != nil {
			return err
		}
	}
	seenNames := make(map[string]struct{}, len(network.Interfaces))
	seenIndexes := make(map[int]struct{}, len(network.Interfaces))
	for _, networkInterface := range network.Interfaces {
		if _, exists := seenNames[networkInterface.Name]; exists {
			return fmt.Errorf("network repeats interface name %q", networkInterface.Name)
		}
		seenNames[networkInterface.Name] = struct{}{}
		if _, exists := seenIndexes[networkInterface.Index]; exists {
			return fmt.Errorf("network repeats interface index %d", networkInterface.Index)
		}
		seenIndexes[networkInterface.Index] = struct{}{}
	}
	return nil
}

func validateNetworkInterface(networkInterface NetworkInterfaceObservation) error {
	if err := validateText("interfaces[].name", networkInterface.Name, MaxInterfaceNameBytes, true); err != nil {
		return err
	}
	if networkInterface.Index <= 0 {
		return fmt.Errorf("interface %q has a non-positive index", networkInterface.Name)
	}
	if networkInterface.MTU <= 0 || networkInterface.MTU > MaxInterfaceMTU {
		return fmt.Errorf("interface %q has an unsupported MTU", networkInterface.Name)
	}
	if networkInterface.OperationalState != "" {
		if err := validateEnum("interfaces[].operational_state", string(networkInterface.OperationalState),
			string(OperStateUp), string(OperStateDown), string(OperStateDormant),
			string(OperStateLowerLayerDown), string(OperStateUnknown),
			string(OperStateNotPresent), string(OperStateTesting)); err != nil {
			return err
		}
	}
	// Unreadable link speed is an absence. Zero would be divided into a
	// utilisation percentage and produce an infinity, which is why the field is
	// a pointer and why zero is not a legal value on it.
	if networkInterface.LinkSpeedMbps != nil {
		if *networkInterface.LinkSpeedMbps == 0 || *networkInterface.LinkSpeedMbps > MaxLinkSpeedMbps {
			return fmt.Errorf("interface %q has an unsupported link speed", networkInterface.Name)
		}
	}
	for _, field := range []struct {
		name  string
		value uint64
	}{
		{"rx_bytes", networkInterface.RXBytes},
		{"rx_packets", networkInterface.RXPackets},
		{"rx_errors", networkInterface.RXErrors},
		{"rx_dropped", networkInterface.RXDropped},
		{"tx_bytes", networkInterface.TXBytes},
		{"tx_packets", networkInterface.TXPackets},
		{"tx_errors", networkInterface.TXErrors},
		{"tx_dropped", networkInterface.TXDropped},
	} {
		if err := withinInt64("interfaces[].counter "+field.name, field.value); err != nil {
			return err
		}
	}
	return nil
}

func validateTCPObservation(tcp TCPObservation) error {
	if err := validateText("tcp.counter_epoch", tcp.CounterEpoch, MaxCounterEpochBytes, true); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value uint64
	}{
		{"tcp.active_opens", tcp.ActiveOpens},
		{"tcp.passive_opens", tcp.PassiveOpens},
		{"tcp.attempt_fails", tcp.AttemptFails},
		{"tcp.estab_resets", tcp.EstabResets},
		{"tcp.in_segments", tcp.InSegments},
		{"tcp.out_segments", tcp.OutSegments},
		{"tcp.retrans_segments", tcp.RetransSegments},
		{"tcp.current_established", tcp.CurrentEstablished},
	} {
		if err := withinInt64(field.name, field.value); err != nil {
			return err
		}
	}
	return nil
}

func validateSocketObservation(sockets SocketObservation) error {
	for _, field := range []struct {
		name  string
		value uint64
	}{
		{"sockets.tcp_in_use", sockets.TCPInUse},
		{"sockets.tcp_orphan", sockets.TCPOrphan},
		{"sockets.tcp_time_wait", sockets.TCPTimeWait},
		{"sockets.udp_in_use", sockets.UDPInUse},
	} {
		if err := withinInt64(field.name, field.value); err != nil {
			return err
		}
	}
	for _, field := range []struct {
		name  string
		value *uint64
	}{
		{"sockets.conntrack_current", sockets.ConntrackCurrent},
		{"sockets.conntrack_limit", sockets.ConntrackLimit},
	} {
		if field.value == nil {
			continue
		}
		if err := withinInt64(field.name, *field.value); err != nil {
			return err
		}
	}
	// The pair is all-or-nothing. One alone cannot produce an occupancy ratio,
	// and a container that cannot read conntrack at all must say so with an
	// Unavailable token rather than by reporting half a limit.
	if (sockets.ConntrackCurrent == nil) != (sockets.ConntrackLimit == nil) {
		return fmt.Errorf("sockets conntrack_current and conntrack_limit must be present together")
	}
	return nil
}

func validateProcessObservation(processes ProcessObservation) error {
	if err := validateProcessMetrics("processes.agent", processes.Agent); err != nil {
		return err
	}
	if processes.Core != nil {
		if err := validateProcessMetrics("processes.core", *processes.Core); err != nil {
			return err
		}
	}
	return nil
}

func validateProcessMetrics(name string, metrics ProcessMetrics) error {
	if metrics.StartedAtMS <= 0 || metrics.StartedAtMS > maxUnixMilli {
		return fmt.Errorf("%s.started_at_ms must be a positive unix millisecond timestamp", name)
	}
	// The epoch must be stable across one process instance. A per-sample random
	// value would break every difference the panel takes, silently, while still
	// looking well-formed.
	if err := validateText(name+".counter_epoch", metrics.CounterEpoch, MaxCounterEpochBytes, true); err != nil {
		return err
	}
	for _, field := range []struct {
		fieldName string
		value     *uint64
	}{
		{"cpu_time", metrics.CPUTime},
		{"cpu_time_units_per_second", metrics.CPUTimeUnitsPerSecond},
		{"fd_limit", metrics.FDLimit},
	} {
		if field.value == nil {
			continue
		}
		if err := withinInt64(name+"."+field.fieldName, *field.value); err != nil {
			return err
		}
	}
	// The pair is all-or-nothing, and a units-per-second of zero would turn the
	// ratio into a division by zero. An agent that cannot read AT_CLKTCK reports
	// RSS, FDs and threads with both CPU fields absent.
	if (metrics.CPUTime == nil) != (metrics.CPUTimeUnitsPerSecond == nil) {
		return fmt.Errorf("%s cpu_time and cpu_time_units_per_second must be present together", name)
	}
	if metrics.CPUTimeUnitsPerSecond != nil && *metrics.CPUTimeUnitsPerSecond == 0 {
		return fmt.Errorf("%s cpu_time_units_per_second must be greater than zero", name)
	}
	for _, field := range []struct {
		fieldName string
		value     uint64
	}{
		{"rss_bytes", metrics.RSSBytes},
		{"open_fds", metrics.OpenFDs},
		{"threads", metrics.Threads},
	} {
		if err := withinInt64(name+"."+field.fieldName, field.value); err != nil {
			return err
		}
	}
	return nil
}

func validateRuntimeObservation(runtime RuntimeObservation) error {
	if runtime.AgentStartedAtMS <= 0 || runtime.AgentStartedAtMS > maxUnixMilli {
		return fmt.Errorf("runtime.agent_started_at_ms must be a positive unix millisecond timestamp")
	}
	for _, field := range []struct {
		name  string
		value int64
	}{
		{"runtime.last_sync_success_at_ms", runtime.LastSyncSuccessAtMS},
		{"runtime.last_sync_failure_at_ms", runtime.LastSyncFailureAtMS},
	} {
		// Zero is legal here and means "has not happened yet" — the one place a
		// zero timestamp is meaningful, and the reason this field is checked as
		// a range rather than for positivity.
		if field.value < 0 || field.value > maxUnixMilli {
			return fmt.Errorf("%s is out of range", field.name)
		}
	}
	for _, field := range []struct {
		name  string
		value uint64
	}{
		{"runtime.core_restart_count", runtime.CoreRestartCount},
		{"runtime.consecutive_sync_failures", runtime.ConsecutiveSyncFailures},
		{"runtime.sync_success_count", runtime.SyncSuccessCount},
		{"runtime.sync_failure_count", runtime.SyncFailureCount},
		{"runtime.collector_duration_ms", runtime.CollectorDurationMS},
	} {
		if err := withinInt64(field.name, field.value); err != nil {
			return err
		}
	}
	for _, field := range []struct {
		name  string
		value *uint64
	}{
		{"runtime.last_round_trip_ms", runtime.LastRoundTripMS},
		{"runtime.last_request_bytes", runtime.LastRequestBytes},
		{"runtime.last_response_bytes", runtime.LastResponseBytes},
	} {
		if field.value == nil {
			continue
		}
		if err := withinInt64(field.name, *field.value); err != nil {
			return err
		}
	}
	return nil
}

func validateTuningObservation(tuning TuningObservation) error {
	if len(tuning.TCPAvailableCongestionControls) > MaxCongestionControls {
		return fmt.Errorf("tuning holds %d congestion controls, at most %d are allowed",
			len(tuning.TCPAvailableCongestionControls), MaxCongestionControls)
	}
	for _, control := range tuning.TCPAvailableCongestionControls {
		if len(control) > MaxCongestionControlBytes {
			return fmt.Errorf("congestion control %q exceeds %d bytes", control, MaxCongestionControlBytes)
		}
		// The value is a kernel algorithm name, and it is rendered in the panel.
		// Constraining it to a lowercase token keeps it from becoming a place to
		// put arbitrary text — which is the same reason every other free-form
		// field in this subtree is bounded.
		if !validToken(control) {
			return fmt.Errorf("congestion control %q is not a lowercase token", control)
		}
	}
	// The default is what NEW sockets receive, not what the core's established
	// connections are using. It is still a kernel-provided name, so it gets the
	// same treatment as the list above.
	if tuning.TCPDefaultCongestionControl != "" {
		if len(tuning.TCPDefaultCongestionControl) > MaxCongestionControlBytes ||
			!validToken(tuning.TCPDefaultCongestionControl) {
			return fmt.Errorf("default congestion control is not a lowercase token")
		}
	}
	if tuning.DefaultQdisc != "" {
		if len(tuning.DefaultQdisc) > MaxCongestionControlBytes || !validToken(tuning.DefaultQdisc) {
			return fmt.Errorf("default qdisc is not a lowercase token")
		}
	}
	return nil
}

// validSampleID checks the exact 32-character lowercase hex shape. The length
// is part of the identity, not a bound: the panel stores it as a fixed-width
// column and is idempotent on it, so a normalisable variant would give one
// sample two identities.
func validSampleID(value string) bool {
	if len(value) != SampleIDBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

// withinInt64 keeps every unsigned counter inside the signed range all three
// dialects store. A uint64 above MaxInt64 would be written correctly by none of
// them and read back as a negative, which the panel would then have to classify
// as corruption — better to refuse the sample than to store a lie.
func withinInt64(name string, value uint64) error {
	if value > math.MaxInt64 {
		return fmt.Errorf("%s exceeds the maximum storable counter value", name)
	}
	return nil
}

func validMetricFloat(name string, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return fmt.Errorf("%s is not a finite number", name)
	}
	if value < 0 {
		return fmt.Errorf("%s must be non-negative", name)
	}
	return nil
}

// validateText enforces UTF-8 well-formedness and a byte bound. Invalid UTF-8
// is rejected rather than scrubbed: the values reach an administrator's screen
// and a database column, and a silently repaired string is one that no longer
// matches what the agent measured.
func validateText(name, value string, maxBytes int, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, maxBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	return nil
}

func validateEnum(name, value string, allowed ...string) error {
	for _, candidate := range allowed {
		if value == candidate {
			return nil
		}
	}
	return fmt.Errorf("%s %q is unsupported", name, value)
}
