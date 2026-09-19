// Package protocol is a compatibility re-export of
// github.com/KazuhaHub/passwall-protocol/protocol.
//
// The wire contract moved to its own module so Passwall-Sub-Panel no longer has
// to depend on this one for it. Every name below is an ALIAS to the new
// package's name, not a copy: the compiler treats protocol.NodeReport and
// passwallprotocol.NodeReport as the same type, so the two import paths can be
// mixed in one build graph while both are in use.
//
// Types are aliases, constants are constants, and functions are wrappers that
// call straight through. There is no second implementation here, and there must
// not be: the two packages have to agree on the bytes, and two copies of a codec
// is how they stop agreeing.
//
// The one exported variable cannot be an alias — Go has no variable aliasing —
// so it is initialized from the new package's variable at program start. It is
// read-only in both packages, so the copy is the value.
//
// This layer goes away when PSP stops reaching this module for anything else.
// Removing it is a public API removal with its own notice period, not a cleanup.
package protocol

import p "github.com/KazuhaHub/passwall-protocol/protocol"

type AgentUpgradeArgs = p.AgentUpgradeArgs
type AgentUpgradeResult = p.AgentUpgradeResult
type CPUObservation = p.CPUObservation
type CgroupCPUObservation = p.CgroupCPUObservation
type CgroupMemoryObservation = p.CgroupMemoryObservation
type Client = p.Client
type ClientCounters = p.ClientCounters
type ClientKey = p.ClientKey
type Compatibility = p.Compatibility
type ConfigBody = p.ConfigBody
type CoreSelection = p.CoreSelection
type Credential = p.Credential
type DataFilesystemScope = p.DataFilesystemScope
type Deployment = p.Deployment
type DiagnosticsArgs = p.DiagnosticsArgs
type DiagnosticsCheck = p.DiagnosticsCheck
type DiagnosticsCheckStatus = p.DiagnosticsCheckStatus
type DiagnosticsEvent = p.DiagnosticsEvent
type DiagnosticsResult = p.DiagnosticsResult
type DiagnosticsRuntime = p.DiagnosticsRuntime
type DiagnosticsSeverity = p.DiagnosticsSeverity
type DiagnosticsState = p.DiagnosticsState
type DirectivesBody = p.DirectivesBody
type ETag = p.ETag
type Envelope = p.Envelope
type FilesystemObservation = p.FilesystemObservation
type GateState = p.GateState
type HostObservation = p.HostObservation
type HostScope = p.HostScope
type IPShadowEntry = p.IPShadowEntry
type Issue = p.Issue
type Listener = p.Listener
type ListenerCounters = p.ListenerCounters
type ListenerKey = p.ListenerKey
type LoadObservation = p.LoadObservation
type MemoryObservation = p.MemoryObservation
type NetworkInterfaceObservation = p.NetworkInterfaceObservation
type NetworkObservation = p.NetworkObservation
type NodeReport = p.NodeReport
type ObjectState = p.ObjectState
type ObjectStatus = p.ObjectStatus
type OperationalState = p.OperationalState
type PlatformObservation = p.PlatformObservation
type ProcessMetrics = p.ProcessMetrics
type ProcessObservation = p.ProcessObservation
type QuotaEntry = p.QuotaEntry
type RawConfig = p.RawConfig
type ResourceScope = p.ResourceScope
type RosterBody = p.RosterBody
type RuntimeObservation = p.RuntimeObservation
type SegmentCounts = p.SegmentCounts
type Segment[T any] = p.Segment[T]
type SocketObservation = p.SocketObservation
type StreamState = p.StreamState
type SubjectKey = p.SubjectKey
type SubjectObservation = p.SubjectObservation
type SyncResponse = p.SyncResponse
type SystemCPUObservation = p.SystemCPUObservation
type SystemMemoryObservation = p.SystemMemoryObservation
type TCPObservation = p.TCPObservation
type Task = p.Task
type TaskResult = p.TaskResult
type TuningObservation = p.TuningObservation
type Version = p.Version

const CapabilityHostTelemetry = p.CapabilityHostTelemetry
const CapabilityTaskExecutionV1 = p.CapabilityTaskExecutionV1
const CapabilityTaskExpiryV1 = p.CapabilityTaskExpiryV1
const CheckCodeCollectorHost = p.CheckCodeCollectorHost
const CheckCodeCollectorProcess = p.CheckCodeCollectorProcess
const CheckCodeCoreBinaryDigest = p.CheckCodeCoreBinaryDigest
const CheckCodeCoreConfirmedConfigDigest = p.CheckCodeCoreConfirmedConfigDigest
const CheckCodeCoreSelection = p.CheckCodeCoreSelection
const CheckCodeCredentialPermissions = p.CheckCodeCredentialPermissions
const CheckCodeDataDirAccess = p.CheckCodeDataDirAccess
const CheckCodeInstallationLayout = p.CheckCodeInstallationLayout
const CheckCodeStateSQLiteOpen = p.CheckCodeStateSQLiteOpen
const CheckCodeStateSQLiteQuickCheck = p.CheckCodeStateSQLiteQuickCheck
const DefaultFullReportSeconds = p.DefaultFullReportSeconds
const DefaultHostReportSeconds = p.DefaultHostReportSeconds
const DefaultNextPollSeconds = p.DefaultNextPollSeconds
const DeploymentDocker = p.DeploymentDocker
const DeploymentManual = p.DeploymentManual
const DeploymentSystemd = p.DeploymentSystemd
const DeploymentUnknown = p.DeploymentUnknown
const DiagnosticsCheckFailed = p.DiagnosticsCheckFailed
const DiagnosticsCheckOK = p.DiagnosticsCheckOK
const DiagnosticsCheckUnavailable = p.DiagnosticsCheckUnavailable
const DiagnosticsCheckWarning = p.DiagnosticsCheckWarning
const DiagnosticsEventCollectorUnavailable = p.DiagnosticsEventCollectorUnavailable
const DiagnosticsEventCoreRestarted = p.DiagnosticsEventCoreRestarted
const DiagnosticsEventCoreStarted = p.DiagnosticsEventCoreStarted
const DiagnosticsEventCoreStopped = p.DiagnosticsEventCoreStopped
const DiagnosticsEventSyncFailed = p.DiagnosticsEventSyncFailed
const DiagnosticsEventTaskRejected = p.DiagnosticsEventTaskRejected
const DiagnosticsSchemaVersion = p.DiagnosticsSchemaVersion
const DiagnosticsSectionEvents = p.DiagnosticsSectionEvents
const DiagnosticsSectionHost = p.DiagnosticsSectionHost
const DiagnosticsSectionRuntime = p.DiagnosticsSectionRuntime
const DiagnosticsSectionState = p.DiagnosticsSectionState
const DiagnosticsSeverityError = p.DiagnosticsSeverityError
const DiagnosticsSeverityInfo = p.DiagnosticsSeverityInfo
const DiagnosticsSeverityWarning = p.DiagnosticsSeverityWarning
const FilesystemScopeContainerMount = p.FilesystemScopeContainerMount
const FilesystemScopeHostMount = p.FilesystemScopeHostMount
const FilesystemScopeUnknown = p.FilesystemScopeUnknown
const GateArmed = p.GateArmed
const GateClosed = p.GateClosed
const GateUnconfigured = p.GateUnconfigured
const IssueAttachmentUnknownListener = p.IssueAttachmentUnknownListener
const IssueDirectiveUnknownClient = p.IssueDirectiveUnknownClient
const IssueDirectivesAheadOfRoster = p.IssueDirectivesAheadOfRoster
const IssueHostTelemetryFailed = p.IssueHostTelemetryFailed
const IssueLegacyTaskResultQuarantined = p.IssueLegacyTaskResultQuarantined
const IssueObjectPendingTimeout = p.IssueObjectPendingTimeout
const IssueObjectRejectedTimeout = p.IssueObjectRejectedTimeout
const IssueReportMissingObject = p.IssueReportMissingObject
const IssueRosterAheadOfConfig = p.IssueRosterAheadOfConfig
const IssueTaskIdentityConflict = p.IssueTaskIdentityConflict
const IssueTaskReplayFenced = p.IssueTaskReplayFenced
const MaxBootIDBytes = p.MaxBootIDBytes
const MaxCapabilitiesPerReport = p.MaxCapabilitiesPerReport
const MaxCapabilityBytes = p.MaxCapabilityBytes
const MaxCongestionControlBytes = p.MaxCongestionControlBytes
const MaxCongestionControls = p.MaxCongestionControls
const MaxCounterEpochBytes = p.MaxCounterEpochBytes
const MaxDiagnosticsEvents = p.MaxDiagnosticsEvents
const MaxDiagnosticsNotAfter = p.MaxDiagnosticsNotAfter
const MaxDiagnosticsResultBytes = p.MaxDiagnosticsResultBytes
const MaxDiagnosticsSections = p.MaxDiagnosticsSections
const MaxDiagnosticsSummaryBytes = p.MaxDiagnosticsSummaryBytes
const MaxFullReportSeconds = p.MaxFullReportSeconds
const MaxHostObservationBytes = p.MaxHostObservationBytes
const MaxHostReportSeconds = p.MaxHostReportSeconds
const MaxInterfaceMTU = p.MaxInterfaceMTU
const MaxInterfaceNameBytes = p.MaxInterfaceNameBytes
const MaxIssueCodeBytes = p.MaxIssueCodeBytes
const MaxIssueDetailBytes = p.MaxIssueDetailBytes
const MaxIssueKeyBytes = p.MaxIssueKeyBytes
const MaxIssuesPerReport = p.MaxIssuesPerReport
const MaxKernelReleaseBytes = p.MaxKernelReleaseBytes
const MaxLinkSpeedMbps = p.MaxLinkSpeedMbps
const MaxLogicalCPUs = p.MaxLogicalCPUs
const MaxNetworkInterfaces = p.MaxNetworkInterfaces
const MaxNextPollSeconds = p.MaxNextPollSeconds
const MaxNodeCredentialBytes = p.MaxNodeCredentialBytes
const MaxPlatformFieldBytes = p.MaxPlatformFieldBytes
const MaxSupportedProtocolVersion = p.MaxSupportedProtocolVersion
const MaxSyncBodyBytes = p.MaxSyncBodyBytes
const MaxTaskArgsBytes = p.MaxTaskArgsBytes
const MaxTaskArgsBytesPerResponse = p.MaxTaskArgsBytesPerResponse
const MaxTaskErrorBytes = p.MaxTaskErrorBytes
const MaxTaskErrorCodeBytes = p.MaxTaskErrorCodeBytes
const MaxTaskIDBytes = p.MaxTaskIDBytes
const MaxTaskKindBytes = p.MaxTaskKindBytes
const MaxTaskResultBytes = p.MaxTaskResultBytes
const MaxTaskResultBytesPerReport = p.MaxTaskResultBytesPerReport
const MaxTaskResultsPerReport = p.MaxTaskResultsPerReport
const MaxTasksPerResponse = p.MaxTasksPerResponse
const MaxUnavailableTokenBytes = p.MaxUnavailableTokenBytes
const MaxUnavailableTokens = p.MaxUnavailableTokens
const MinHostReportSeconds = p.MinHostReportSeconds
const MinLogicalCPUs = p.MinLogicalCPUs
const MinNodeCredentialBytes = p.MinNodeCredentialBytes
const MinSupportedProtocolVersion = p.MinSupportedProtocolVersion
const ObjectApplied = p.ObjectApplied
const ObjectBlocked = p.ObjectBlocked
const ObjectPending = p.ObjectPending
const ObjectRejected = p.ObjectRejected
const OperStateDormant = p.OperStateDormant
const OperStateDown = p.OperStateDown
const OperStateLowerLayerDown = p.OperStateLowerLayerDown
const OperStateNotPresent = p.OperStateNotPresent
const OperStateTesting = p.OperStateTesting
const OperStateUnknown = p.OperStateUnknown
const OperStateUp = p.OperStateUp
const ProtocolVersion1 = p.ProtocolVersion1
const SampleIDBytes = p.SampleIDBytes
const ScopeContainer = p.ScopeContainer
const ScopeHost = p.ScopeHost
const ScopeMixed = p.ScopeMixed
const ScopeUnknown = p.ScopeUnknown
const StreamConfig = p.StreamConfig
const StreamDirectives = p.StreamDirectives
const StreamRoster = p.StreamRoster
const TaskErrorExpiredBeforeStart = p.TaskErrorExpiredBeforeStart
const TaskKindAgentUpgradeV1 = p.TaskKindAgentUpgradeV1
const TaskKindDiagnosticsCollectV1 = p.TaskKindDiagnosticsCollectV1
const UnavailableCPUCgroup = p.UnavailableCPUCgroup
const UnavailableCPUSystem = p.UnavailableCPUSystem
const UnavailableConntrack = p.UnavailableConntrack
const UnavailableFilesystemData = p.UnavailableFilesystemData
const UnavailableFilesystemInodes = p.UnavailableFilesystemInodes
const UnavailableLoad = p.UnavailableLoad
const UnavailableMemoryAvailable = p.UnavailableMemoryAvailable
const UnavailableMemoryCgroup = p.UnavailableMemoryCgroup
const UnavailableMemoryCgroupOOM = p.UnavailableMemoryCgroupOOM
const UnavailableMemorySystem = p.UnavailableMemorySystem
const UnavailableNetDefaultRoute = p.UnavailableNetDefaultRoute
const UnavailableNetInterfaces = p.UnavailableNetInterfaces
const UnavailableNetLinkSpeed = p.UnavailableNetLinkSpeed
const UnavailablePlatformDistro = p.UnavailablePlatformDistro
const UnavailablePlatformKernel = p.UnavailablePlatformKernel
const UnavailableProcessAgent = p.UnavailableProcessAgent
const UnavailableProcessCore = p.UnavailableProcessCore
const UnavailableRuntimeSync = p.UnavailableRuntimeSync
const UnavailableSockets = p.UnavailableSockets
const UnavailableTCP = p.UnavailableTCP
const UnavailableTuningCC = p.UnavailableTuningCC
const UnavailableTuningQdisc = p.UnavailableTuningQdisc

var DiagnosticsCheckCodes = p.DiagnosticsCheckCodes

func AgentUpgradeCapabilities() []string                         { return p.AgentUpgradeCapabilities() }
func AssessCompatibility(a0 int, a1 []string) Compatibility      { return p.AssessCompatibility(a0, a1) }
func ComputeTaskInputSHA256(a0 string, a1 []byte) string         { return p.ComputeTaskInputSHA256(a0, a1) }
func Converged(a0, a1 ETag) bool                                 { return p.Converged(a0, a1) }
func DecodeAgentUpgradeArgs(a0 []byte) (AgentUpgradeArgs, error) { return p.DecodeAgentUpgradeArgs(a0) }
func DecodeAgentUpgradeResult(a0 []byte) (AgentUpgradeResult, error) {
	return p.DecodeAgentUpgradeResult(a0)
}
func DecodeDiagnosticsArgs(a0 []byte) (DiagnosticsArgs, error) { return p.DecodeDiagnosticsArgs(a0) }
func DecodeDiagnosticsResult(a0 []byte) (DiagnosticsResult, error) {
	return p.DecodeDiagnosticsResult(a0)
}
func EffectiveFullReportPeriod(a0, a1 int) int             { return p.EffectiveFullReportPeriod(a0, a1) }
func EffectiveHostReportPeriod(a0, a1 int) int             { return p.EffectiveHostReportPeriod(a0, a1) }
func EffectiveProtocolVersion(a0 int) int                  { return p.EffectiveProtocolVersion(a0) }
func IsDiagnosticsEventCode(a0 string) bool                { return p.IsDiagnosticsEventCode(a0) }
func IsDiagnosticsSection(a0 string) bool                  { return p.IsDiagnosticsSection(a0) }
func IsDiagnosticsSeverity(a0 DiagnosticsSeverity) bool    { return p.IsDiagnosticsSeverity(a0) }
func NewClientKey(a0 int64) ClientKey                      { return p.NewClientKey(a0) }
func NewListenerKey(a0 int64) ListenerKey                  { return p.NewListenerKey(a0) }
func NewSubjectKey(a0 int64) SubjectKey                    { return p.NewSubjectKey(a0) }
func ShouldSendFull(a0 Envelope, a1 int) bool              { return p.ShouldSendFull(a0, a1) }
func ShouldSendHost(a0 Envelope, a1 int) bool              { return p.ShouldSendHost(a0, a1) }
func SortDiagnosticsEvents(a0 []DiagnosticsEvent)          { p.SortDiagnosticsEvents(a0) }
func TaskCapability(a0 string) string                      { return p.TaskCapability(a0) }
func ValidateDiagnosticsArgs(a0 DiagnosticsArgs) error     { return p.ValidateDiagnosticsArgs(a0) }
func ValidateDiagnosticsResult(a0 DiagnosticsResult) error { return p.ValidateDiagnosticsResult(a0) }
func ValidateEnvelope(a0 Envelope) error                   { return p.ValidateEnvelope(a0) }
func ValidateHostObservation(a0 HostObservation) error     { return p.ValidateHostObservation(a0) }
func ValidateNodeReport(a0 NodeReport) error               { return p.ValidateNodeReport(a0) }
func ValidateNodeReportBase(a0 NodeReport) error           { return p.ValidateNodeReportBase(a0) }
func ValidateSyncResponse(a0 SyncResponse) error           { return p.ValidateSyncResponse(a0) }
func ValidateTaskResults(a0 []TaskResult) error            { return p.ValidateTaskResults(a0) }
func ValidateTasks(a0 []Task) error                        { return p.ValidateTasks(a0) }
