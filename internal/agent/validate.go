package agent

import (
	"fmt"

	"github.com/KazuhaHub/passwall-node/corecatalog"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func validateConfig(body *protocol.ConfigBody) error {
	if body == nil {
		return fmt.Errorf("config body is required")
	}
	if err := validateCoverage(body.Coverage); err != nil {
		return fmt.Errorf("config coverage: %w", err)
	}
	if err := validateCoreSelection(body.Core); err != nil {
		return fmt.Errorf("config core: %w", err)
	}
	seen := make(map[protocol.ListenerKey]struct{}, len(body.Listeners))
	for i, listener := range body.Listeners {
		if listener.Key == "" {
			return fmt.Errorf("listener %d has no key", i)
		}
		if _, err := listener.Key.RowID(); err != nil {
			return fmt.Errorf("listener %d: %w", i, err)
		}
		if _, exists := seen[listener.Key]; exists {
			return fmt.Errorf("listener key %s appears more than once", listener.Key)
		}
		seen[listener.Key] = struct{}{}
		if len(listener.Config) == 0 {
			return fmt.Errorf("listener %s has empty config", listener.Key)
		}
	}
	if body.Coverage.Entries != len(body.Listeners) {
		return fmt.Errorf("config coverage entries %d do not match %d listeners", body.Coverage.Entries, len(body.Listeners))
	}
	if body.Coverage.Subjects != 0 {
		return fmt.Errorf("config coverage subjects must be zero")
	}
	return nil
}

func validateCoreSelection(selection protocol.CoreSelection) error {
	if selection.Engine == "" && selection.Version == "" && !selection.AllowRestrictedReality {
		return nil
	}
	if selection.Engine != "xray" || selection.Version == "" {
		return fmt.Errorf("engine xray and an exact version are required")
	}
	release, err := corecatalog.Resolve(selection.Engine, selection.Version)
	if err != nil {
		return err
	}
	if release.RequiresConfirmation != selection.AllowRestrictedReality {
		if release.RequiresConfirmation {
			return fmt.Errorf("release %s requires allow_restricted_reality", release.Version)
		}
		return fmt.Errorf("allow_restricted_reality is invalid for unrestricted release %s", release.Version)
	}
	return nil
}

func validateRoster(body *protocol.RosterBody) error {
	if body == nil {
		return fmt.Errorf("roster body is required")
	}
	if !body.MinConfigVersion.Committed() {
		return fmt.Errorf("min_config_version is required")
	}
	if err := validateCoverage(body.Coverage); err != nil {
		return fmt.Errorf("roster coverage: %w", err)
	}
	seen := make(map[protocol.ClientKey]struct{}, len(body.Clients))
	subjects := make(map[protocol.SubjectKey]struct{}, len(body.Clients))
	for i, client := range body.Clients {
		if client.Key == "" || client.Subject == "" {
			return fmt.Errorf("client %d requires client and subject keys", i)
		}
		if _, err := client.Key.RowID(); err != nil {
			return fmt.Errorf("client %d: %w", i, err)
		}
		if _, err := client.Subject.RowID(); err != nil {
			return fmt.Errorf("client %s: %w", client.Key, err)
		}
		if _, exists := seen[client.Key]; exists {
			return fmt.Errorf("client key %s appears more than once", client.Key)
		}
		seen[client.Key] = struct{}{}
		subjects[client.Subject] = struct{}{}
		if client.ExpiresAtMS < 0 {
			return fmt.Errorf("client %s has negative expiry", client.Key)
		}
		switch client.Credentials.Flow {
		case "", "xtls-rprx-vision":
		default:
			return fmt.Errorf("client %s has unsupported flow %q", client.Key, client.Credentials.Flow)
		}
		listeners := make(map[protocol.ListenerKey]struct{}, len(client.Listeners))
		for _, key := range client.Listeners {
			if _, err := key.RowID(); err != nil {
				return fmt.Errorf("client %s attachment: %w", client.Key, err)
			}
			if _, exists := listeners[key]; exists {
				return fmt.Errorf("client %s attaches listener %s more than once", client.Key, key)
			}
			listeners[key] = struct{}{}
		}
	}
	if body.Coverage.Entries != len(body.Clients) {
		return fmt.Errorf("roster coverage entries %d do not match %d clients", body.Coverage.Entries, len(body.Clients))
	}
	if body.Coverage.Subjects != len(subjects) {
		return fmt.Errorf("roster coverage subjects %d do not match %d distinct subjects", body.Coverage.Subjects, len(subjects))
	}
	return nil
}

func validateDirectives(body *protocol.DirectivesBody) error {
	if body == nil {
		return fmt.Errorf("directives body is required")
	}
	if !body.ForRosterVersion.Committed() {
		return fmt.Errorf("for_roster_version is required")
	}
	if err := validateCoverage(body.Coverage); err != nil {
		return fmt.Errorf("directives coverage: %w", err)
	}
	clients := make(map[protocol.ClientKey]struct{}, len(body.Quota))
	for i, quota := range body.Quota {
		if _, err := quota.Client.RowID(); err != nil {
			return fmt.Errorf("quota %d: %w", i, err)
		}
		if _, exists := clients[quota.Client]; exists {
			return fmt.Errorf("quota client %s appears more than once", quota.Client)
		}
		clients[quota.Client] = struct{}{}
		if quota.BaselineBytes < 0 || (quota.HeadroomBytes != nil && *quota.HeadroomBytes < 0) {
			return fmt.Errorf("quota client %s has negative bytes", quota.Client)
		}
		if (quota.PeriodEndsAtMS == 0) != (quota.NextPeriodHeadroomBytes == nil) {
			return fmt.Errorf("quota client %s has an incomplete next-period grant", quota.Client)
		}
		if quota.PeriodEndsAtMS < 0 || (quota.NextPeriodHeadroomBytes != nil && *quota.NextPeriodHeadroomBytes < 0) {
			return fmt.Errorf("quota client %s has a negative next-period grant", quota.Client)
		}
	}
	subjects := make(map[protocol.SubjectKey]struct{}, len(body.IPShadow))
	for i, shadow := range body.IPShadow {
		if _, err := shadow.Subject.RowID(); err != nil {
			return fmt.Errorf("ip_shadow %d: %w", i, err)
		}
		if _, exists := subjects[shadow.Subject]; exists {
			return fmt.Errorf("ip_shadow subject %s appears more than once", shadow.Subject)
		}
		subjects[shadow.Subject] = struct{}{}
		if shadow.IPLimit < 0 {
			return fmt.Errorf("ip_shadow subject %s has negative limit", shadow.Subject)
		}
	}
	if body.Coverage.Entries < len(body.Quota) {
		return fmt.Errorf("directives aggregate coverage entries %d are fewer than %d local quota entries", body.Coverage.Entries, len(body.Quota))
	}
	if body.Coverage.Subjects < len(subjects) {
		return fmt.Errorf("directives aggregate coverage subjects %d are fewer than %d local IP-shadow subjects", body.Coverage.Subjects, len(subjects))
	}
	return nil
}

func validateCoverage(coverage protocol.SegmentCounts) error {
	if coverage.Entries < 0 || coverage.EntriesStale < 0 || coverage.Subjects < 0 {
		return fmt.Errorf("counts must be non-negative")
	}
	if coverage.EntriesStale > coverage.Entries {
		return fmt.Errorf("stale entries %d exceed entries %d", coverage.EntriesStale, coverage.Entries)
	}
	return nil
}
