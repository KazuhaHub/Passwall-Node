package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const retainedClosedCoreConnections = 2000

func (s *Store) ApplyCoreTrafficEvents(ctx context.Context, processIdentity string, reset bool, events []state.CoreTrafficEvent) error {
	if err := validateProcessIdentity(processIdentity); err != nil {
		return err
	}
	for index, event := range events {
		if err := validateCoreTrafficEvent(event); err != nil {
			return fmt.Errorf("core traffic event %d: %w", index, err)
		}
		if reset && !event.Absolute {
			return fmt.Errorf("core traffic event %d: reset snapshots require absolute events", index)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin core traffic events: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if reset {
		if err := verifyCoreTrafficResetCoverage(ctx, tx, processIdentity, events); err != nil {
			return err
		}
	}
	if err := prepareCoreTrafficStream(ctx, tx, processIdentity, reset); err != nil {
		return err
	}
	for _, event := range events {
		if err := applyCoreTrafficEvent(ctx, tx, processIdentity, event); err != nil {
			return fmt.Errorf("apply core traffic connection %s: %w", event.ConnectionID, err)
		}
	}
	if reset {
		if _, err := tx.ExecContext(ctx, `UPDATE core_traffic_stream SET ready = 1 WHERE id = 1 AND process_identity = ?`, processIdentity); err != nil {
			return fmt.Errorf("mark core traffic stream ready: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM core_connection_traffic
		WHERE process_identity = ? AND closed = 1 AND rowid NOT IN (
			SELECT rowid FROM core_connection_traffic
			WHERE process_identity = ? AND closed = 1
			ORDER BY closed_at_ms DESC, rowid DESC LIMIT ?
		)`, processIdentity, processIdentity, retainedClosedCoreConnections); err != nil {
		return fmt.Errorf("prune core connection ledger: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit core traffic events: %w", err)
	}
	return nil
}

func verifyCoreTrafficResetCoverage(ctx context.Context, tx *sql.Tx, identity string, events []state.CoreTrafficEvent) error {
	var current string
	var ready int
	err := tx.QueryRowContext(ctx, `SELECT process_identity, ready FROM core_traffic_stream WHERE id = 1`).Scan(&current, &ready)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read core traffic stream before reset: %w", err)
	}
	if current != identity || ready != 1 {
		return nil
	}
	seen := make(map[string]struct{}, len(events))
	for _, event := range events {
		seen[event.ConnectionID] = struct{}{}
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT connection_id FROM core_connection_traffic WHERE process_identity = ? AND closed = 0`, identity)
	if err != nil {
		return fmt.Errorf("query open core connections before reset: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var connectionID string
		if err := rows.Scan(&connectionID); err != nil {
			return fmt.Errorf("scan open core connection before reset: %w", err)
		}
		if _, exists := seen[connectionID]; !exists {
			return fmt.Errorf("%w: open connection %s is absent from the reset snapshot", state.ErrCoreTrafficGap, connectionID)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate open core connections before reset: %w", err)
	}
	return nil
}

func (s *Store) CoreTrafficSnapshot(ctx context.Context, processIdentity string) (state.CoreTrafficSnapshot, error) {
	if err := validateProcessIdentity(processIdentity); err != nil {
		return state.CoreTrafficSnapshot{}, err
	}
	var storedIdentity string
	var ready int
	if err := s.db.QueryRowContext(ctx, `SELECT process_identity, ready FROM core_traffic_stream WHERE id = 1`).Scan(&storedIdentity, &ready); errors.Is(err, sql.ErrNoRows) {
		return state.CoreTrafficSnapshot{}, nil
	} else if err != nil {
		return state.CoreTrafficSnapshot{}, fmt.Errorf("read core traffic stream: %w", err)
	}
	if storedIdentity != processIdentity || ready != 1 {
		return state.CoreTrafficSnapshot{}, nil
	}
	result := state.CoreTrafficSnapshot{
		Ready: true, Clients: make(map[protocol.ClientKey]state.CoreTrafficValue),
		Listeners: make(map[protocol.ListenerKey]state.CoreTrafficValue),
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT client_key, up_bytes, down_bytes FROM core_client_traffic WHERE process_identity = ?`, processIdentity)
	if err != nil {
		return state.CoreTrafficSnapshot{}, fmt.Errorf("query core client traffic: %w", err)
	}
	for rows.Next() {
		var key protocol.ClientKey
		var value state.CoreTrafficValue
		if err := rows.Scan(&key, &value.UpBytes, &value.DownBytes); err != nil {
			rows.Close()
			return state.CoreTrafficSnapshot{}, fmt.Errorf("scan core client traffic: %w", err)
		}
		result.Clients[key] = value
	}
	if err := rows.Close(); err != nil {
		return state.CoreTrafficSnapshot{}, fmt.Errorf("close core client traffic: %w", err)
	}
	rows, err = s.db.QueryContext(ctx, `
		SELECT listener_key, up_bytes, down_bytes FROM core_listener_traffic WHERE process_identity = ?`, processIdentity)
	if err != nil {
		return state.CoreTrafficSnapshot{}, fmt.Errorf("query core listener traffic: %w", err)
	}
	for rows.Next() {
		var key protocol.ListenerKey
		var value state.CoreTrafficValue
		if err := rows.Scan(&key, &value.UpBytes, &value.DownBytes); err != nil {
			rows.Close()
			return state.CoreTrafficSnapshot{}, fmt.Errorf("scan core listener traffic: %w", err)
		}
		result.Listeners[key] = value
	}
	if err := rows.Close(); err != nil {
		return state.CoreTrafficSnapshot{}, fmt.Errorf("close core listener traffic: %w", err)
	}
	rows, err = s.db.QueryContext(ctx, `
		SELECT client_key, source_ip FROM core_connection_traffic
		WHERE process_identity = ? AND closed = 0 ORDER BY client_key, source_ip`, processIdentity)
	if err != nil {
		return state.CoreTrafficSnapshot{}, fmt.Errorf("query live core connection IPs: %w", err)
	}
	seenIP := make(map[protocol.ClientKey]map[string]struct{})
	for rows.Next() {
		var key protocol.ClientKey
		var sourceIP string
		if err := rows.Scan(&key, &sourceIP); err != nil {
			rows.Close()
			return state.CoreTrafficSnapshot{}, fmt.Errorf("scan live core connection IP: %w", err)
		}
		if seenIP[key] == nil {
			seenIP[key] = make(map[string]struct{})
		}
		seenIP[key][sourceIP] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return state.CoreTrafficSnapshot{}, fmt.Errorf("close live core connection IPs: %w", err)
	}
	for key, addresses := range seenIP {
		value := result.Clients[key]
		for address := range addresses {
			value.LiveIPs = append(value.LiveIPs, address)
		}
		sort.Strings(value.LiveIPs)
		result.Clients[key] = value
	}
	return result, nil
}

func prepareCoreTrafficStream(ctx context.Context, tx *sql.Tx, identity string, reset bool) error {
	var current string
	var ready int
	err := tx.QueryRowContext(ctx, `SELECT process_identity, ready FROM core_traffic_stream WHERE id = 1`).Scan(&current, &ready)
	if errors.Is(err, sql.ErrNoRows) {
		if !reset {
			return errors.New("core traffic stream requires an initial reset")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO core_traffic_stream (id, process_identity, ready) VALUES (1, ?, 0)`, identity); err != nil {
			return fmt.Errorf("create core traffic stream: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read core traffic stream: %w", err)
	}
	if current == identity {
		if !reset && ready != 1 {
			return errors.New("core traffic stream is not initialized")
		}
		return nil
	}
	if !reset {
		return errors.New("new core process traffic stream requires an initial reset")
	}
	// Carry the prior process's durable totals forward before replacing its
	// connection ledger. This closes the restart-between-observations loss gap.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO core_client_traffic (process_identity, client_key, up_bytes, down_bytes)
		SELECT ?, client_key, up_bytes, down_bytes FROM core_client_traffic WHERE process_identity = ?
		ON CONFLICT(process_identity, client_key) DO UPDATE SET
			up_bytes = excluded.up_bytes, down_bytes = excluded.down_bytes`, identity, current); err != nil {
		return fmt.Errorf("carry forward core client traffic: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO core_listener_traffic (process_identity, listener_key, up_bytes, down_bytes)
		SELECT ?, listener_key, up_bytes, down_bytes FROM core_listener_traffic WHERE process_identity = ?
		ON CONFLICT(process_identity, listener_key) DO UPDATE SET
			up_bytes = excluded.up_bytes, down_bytes = excluded.down_bytes`, identity, current); err != nil {
		return fmt.Errorf("carry forward core listener traffic: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM core_connection_traffic`); err != nil {
		return fmt.Errorf("replace core connection ledger: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM core_client_traffic WHERE process_identity != ?`, identity); err != nil {
		return fmt.Errorf("prune prior core client traffic: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM core_listener_traffic WHERE process_identity != ?`, identity); err != nil {
		return fmt.Errorf("prune prior core listener traffic: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE core_traffic_stream SET process_identity = ?, ready = 0 WHERE id = 1`, identity); err != nil {
		return fmt.Errorf("replace core traffic stream: %w", err)
	}
	return nil
}

func applyCoreTrafficEvent(ctx context.Context, tx *sql.Tx, identity string, event state.CoreTrafficEvent) error {
	var storedClient protocol.ClientKey
	var storedListener protocol.ListenerKey
	var storedIP string
	var storedUp, storedDown int64
	var storedClosed int
	err := tx.QueryRowContext(ctx, `
		SELECT client_key, listener_key, source_ip, up_bytes, down_bytes, closed
		FROM core_connection_traffic WHERE process_identity = ? AND connection_id = ?`, identity, event.ConnectionID,
	).Scan(&storedClient, &storedListener, &storedIP, &storedUp, &storedDown, &storedClosed)
	missing := errors.Is(err, sql.ErrNoRows)
	if err != nil && !missing {
		return fmt.Errorf("read connection ledger: %w", err)
	}
	if missing && !event.Absolute {
		return errors.New("delta arrived before absolute connection metadata")
	}
	clientKey, listenerKey, sourceIP := event.ClientKey, event.ListenerKey, event.SourceIP
	if !missing {
		if clientKey != "" && clientKey != storedClient || listenerKey != "" && listenerKey != storedListener || sourceIP != "" && sourceIP != storedIP {
			return errors.New("connection identity metadata changed")
		}
		clientKey, listenerKey, sourceIP = storedClient, storedListener, storedIP
		if storedClosed == 1 && !event.Closed {
			return errors.New("closed connection received a later open event")
		}
	}
	up, down := event.UpBytes, event.DownBytes
	if !event.Absolute {
		var ok bool
		up, ok = addNonNegative(storedUp, event.UpBytes)
		if !ok {
			return errors.New("connection uplink counter overflow")
		}
		down, ok = addNonNegative(storedDown, event.DownBytes)
		if !ok {
			return errors.New("connection downlink counter overflow")
		}
	} else if !missing && (up < storedUp || down < storedDown) {
		return errors.New("absolute connection counter moved backwards")
	}
	deltaUp, deltaDown := up-storedUp, down-storedDown
	if missing {
		deltaUp, deltaDown = up, down
	}
	if err := incrementCoreAggregate(ctx, tx, "core_client_traffic", "client_key", identity, string(clientKey), deltaUp, deltaDown); err != nil {
		return err
	}
	if err := incrementCoreAggregate(ctx, tx, "core_listener_traffic", "listener_key", identity, string(listenerKey), deltaUp, deltaDown); err != nil {
		return err
	}
	closed := 0
	if event.Closed || storedClosed == 1 {
		closed = 1
	}
	closedAt := event.ClosedAtMS
	if closedAt == 0 && !missing && storedClosed == 1 {
		_ = tx.QueryRowContext(ctx, `SELECT closed_at_ms FROM core_connection_traffic WHERE process_identity = ? AND connection_id = ?`, identity, event.ConnectionID).Scan(&closedAt)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO core_connection_traffic
			(process_identity, connection_id, client_key, listener_key, source_ip, up_bytes, down_bytes, closed, closed_at_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(process_identity, connection_id) DO UPDATE SET
			up_bytes = excluded.up_bytes, down_bytes = excluded.down_bytes,
			closed = excluded.closed, closed_at_ms = excluded.closed_at_ms`,
		identity, event.ConnectionID, clientKey, listenerKey, sourceIP, up, down, closed, closedAt,
	); err != nil {
		return fmt.Errorf("write connection ledger: %w", err)
	}
	return nil
}

func incrementCoreAggregate(ctx context.Context, tx *sql.Tx, table, keyColumn, identity, key string, up, down int64) error {
	var currentUp, currentDown int64
	query := fmt.Sprintf(`SELECT up_bytes, down_bytes FROM %s WHERE process_identity = ? AND %s = ?`, table, keyColumn)
	err := tx.QueryRowContext(ctx, query, identity, key).Scan(&currentUp, &currentDown)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read core traffic aggregate: %w", err)
	}
	newUp, ok := addNonNegative(currentUp, up)
	if !ok {
		return errors.New("core uplink aggregate overflow")
	}
	newDown, ok := addNonNegative(currentDown, down)
	if !ok {
		return errors.New("core downlink aggregate overflow")
	}
	statement := fmt.Sprintf(`
		INSERT INTO %s (process_identity, %s, up_bytes, down_bytes) VALUES (?, ?, ?, ?)
		ON CONFLICT(process_identity, %s) DO UPDATE SET up_bytes = excluded.up_bytes, down_bytes = excluded.down_bytes`,
		table, keyColumn, keyColumn)
	if _, err := tx.ExecContext(ctx, statement, identity, key, newUp, newDown); err != nil {
		return fmt.Errorf("write core traffic aggregate: %w", err)
	}
	return nil
}

func validateProcessIdentity(identity string) error {
	if strings.TrimSpace(identity) == "" || strings.TrimSpace(identity) != identity || len(identity) > 512 {
		return errors.New("core process identity must contain 1..512 canonical bytes")
	}
	return nil
}

func validateCoreTrafficEvent(event state.CoreTrafficEvent) error {
	if strings.TrimSpace(event.ConnectionID) == "" || strings.TrimSpace(event.ConnectionID) != event.ConnectionID || len(event.ConnectionID) > 128 {
		return errors.New("connection ID must contain 1..128 canonical bytes")
	}
	if _, err := event.ClientKey.RowID(); err != nil {
		return fmt.Errorf("client key: %w", err)
	}
	if _, err := event.ListenerKey.RowID(); err != nil {
		return fmt.Errorf("listener key: %w", err)
	}
	address, err := netip.ParseAddr(event.SourceIP)
	if err != nil || address.String() != event.SourceIP {
		return errors.New("source IP must be canonical")
	}
	if event.UpBytes < 0 || event.DownBytes < 0 || event.ClosedAtMS < 0 || event.Closed != (event.ClosedAtMS > 0) {
		return errors.New("traffic counters and closed timestamp are invalid")
	}
	return nil
}

func addNonNegative(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, false
	}
	return left + right, true
}
