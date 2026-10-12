import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync } from 'node:fs'
import { readAuditPressureObservation } from './audit-pressure-observation.mjs'

const sample = () => ({ schema_version: 1, go_heap_alloc_bytes: 100000, go_heap_inuse_bytes: 200000, go_heap_objects: 100, go_goroutines: 20,
  lanes: ['block', 'observe', 'trial', 'usage'].map((kind, i) => ({ kind, keys: 0, key_limit: [20000, 10000, 10000, 50000][i], hours: 0, pending: 0, pending_rows: 0, pending_bytes: 0, retained_dropped_events: 0, retained_unmatched_events: 0 })) })
const line = value => `2026/10/12 20:00:00.123456 [Info] passwall-node: audit_pressure=${JSON.stringify(value)}\n`

test('only fixed numeric observations can leave the private journal', () => {
  assert.deepEqual(readAuditPressureObservation(line(sample())), sample())
  assert.equal(readAuditPressureObservation('private-site.example accepted usr_7\n'), undefined)
  assert.throws(() => readAuditPressureObservation('2026/10/12 20:00:00.123456 [Info] passwall-node: audit_pressure={private-person}\n'), error => !error.message.includes('private-person'))
  for (const change of [
    s => { s.subject = 'private' }, s => { s.schema_version = 2 }, s => { s.go_heap_alloc_bytes = 300000 },
    s => { s.lanes[0].batch_id = 'private' }, s => { s.lanes[0].kind = 'user@example' },
    s => { s.lanes[0].keys = 20001 }, s => { s.lanes[1].key_limit = 20000 },
    s => { s.lanes[2].pending = 2 }, s => { s.lanes[3].pending_bytes = 1 },
    s => { s.lanes[1].hours = 51 }, s => { s.lanes[1].retained_dropped_events = 1.5 },
  ]) { const value = sample(); change(value); assert.throws(() => readAuditPressureObservation(line(value))) }
  const pending = sample(); Object.assign(pending.lanes[0], { pending: 1, pending_rows: 1, pending_bytes: 100 })
  readAuditPressureObservation(line(pending))
})

test('observer is explicitly enabled and snapshots do not serialize private pending payloads', () => {
  const main = readFileSync(new URL('../cmd/node/main.go', import.meta.url), 'utf8')
  assert(main.includes('"audit-metrics", false'))
  assert(main.includes('if parsed.AuditMetrics'))
  const snapshot = readFileSync(new URL('../internal/agent/audit/pressure.go', import.meta.url), 'utf8')
  for (const forbidden of ['json.Marshal', 'clone(', '.Next(', '.Acknowledge(', '.expire(']) assert(!snapshot.includes(forbidden), forbidden)
  assert(snapshot.includes('lane.pendingBytes'))
})
