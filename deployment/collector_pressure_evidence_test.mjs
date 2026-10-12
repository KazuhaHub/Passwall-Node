import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync } from 'node:fs'
import { checkCollectorPressureEvidence, checkCollectorPressureMetrics, sanitizeCollectorPressureResults } from './collector-pressure-evidence.mjs'

const good = () => {
  const lanes = Object.entries({ block: 20000, observe: 10000, trial: 10000, usage: 50000 }).map(([kind, limit]) => ({ kind, key_limit: limit, keys: limit, pending_rows: 2000, pending_bytes: 700000, dropped_events: 2, unmatched: 0, slots: kind === 'block' ? 4 : 1, anonymous_rows: kind === 'trial' ? 2000 : 0, identified_rows: kind === 'trial' ? 0 : 2000 }))
  return { schema_version: 1, iterations: 1, total_keys: 90000, pending_count: 4, pending_bytes: 2800000, retained_heap_bytes: 80000000, sampled_peak_heap_bytes: 140000000, lanes }
}
const Package = 'github.com/KazuhaHub/passwall-node/v4/internal/agent/audit'
const Test = 'TestNativeCollectorPressure'
const events = () => [{ Action: 'start', Package }, { Action: 'run', Package, Test }, { Action: 'pass', Package, Test }, { Action: 'pass', Package }]
const encode = rows => rows.map(row => JSON.stringify(row)).join('\n') + '\n'

test('collector report requires unchanged full production limits, four pending bounds and exact isolation accounting', () => {
  assert.equal(checkCollectorPressureMetrics(JSON.stringify(good())).keys, 90000)
  for (const change of [
    r => { r.iterations = 2 }, r => { r.total_keys-- }, r => { r.pending_count = 5 },
    r => { r.pending_bytes-- }, r => { r.lanes.pop() }, r => { r.lanes[1] = r.lanes[0] },
    r => { r.lanes[0].key_limit = 10000 }, r => { r.lanes[0].keys++ }, r => { r.lanes[0].keys-- },
    r => { r.lanes[0].pending_bytes = 1048577 }, r => { r.lanes[0].pending_rows = 4097 },
    r => { r.lanes[3].pending_rows = 8193 }, r => { r.lanes[0].slots = 3 }, r => { r.lanes[1].slots = 0 },
    r => { r.lanes[0].dropped_events = 0 }, r => { r.lanes[1].unmatched = 1 },
    r => { r.lanes[2].identified_rows++; r.lanes[2].anonymous_rows-- },
    r => { r.lanes[0].anonymous_rows++; r.lanes[0].identified_rows-- },
    r => { r.lanes[0].kind = 'private' }, r => { r.lanes[0].subject = 'private' },
    r => { r.retained_heap_bytes = 0 }, r => { r.sampled_peak_heap_bytes = 1 },
    r => { r.sampled_peak_heap_bytes = Number.MAX_SAFE_INTEGER + 1 }, r => { r.credential = 'private' },
  ]) { const value = good(); change(value); assert.throws(() => checkCollectorPressureMetrics(JSON.stringify(value))) }
})

test('collector identity must execute once and private or unknown identities cannot replace its package result', () => {
  const rows = events(), report = JSON.stringify(good())
  const safe = sanitizeCollectorPressureResults(encode([...rows, { Action: 'output', Output: 'credential private destination' }]))
  assert(!safe.includes('credential'))
  checkCollectorPressureEvidence(safe, report)
  for (const rejected of [
    rows.slice(0, -1), rows.filter(row => row.Action !== 'run'), [...rows, rows[1]], [...rows, rows[2]], [...rows, rows[3]],
    rows.map(row => row.Test ? { ...row, Test: 'Unknown' } : row),
    rows.map(row => row.Test && row.Action === 'pass' ? { ...row, Action: 'fail' } : row),
    rows.map(row => row.Test && row.Action === 'pass' ? { ...row, Action: 'skip' } : row),
    rows.map(row => ({ ...row, Package: 'private' })),
    [...rows.slice(0, -1), { Action: 'pass', Package, Test: 'Unknown' }], [rows[0], ...rows],
  ]) assert.throws(() => checkCollectorPressureEvidence(sanitizeCollectorPressureResults(encode(rejected)), report))
  assert.throws(() => checkCollectorPressureEvidence(encode([...rows, { Action: 'output', Package, Output: 'private' }]), report))
})

test('hosted collector pressure gate keeps its tagged source checked and measures a single actual iteration', () => {
  const workflow = readFileSync(new URL('../.github/workflows/test.yml', import.meta.url), 'utf8')
  for (const required of ['  collector-pressure:', 'go vet -tags audit_pressure ./internal/agent/audit', '-test.benchtime=1x', '^TestNativeCollectorPressure$', 'NODE_COLLECTOR_PRESSURE_METRICS', 'deployment/collector-pressure-evidence.mjs sanitize', 'native-collector-pressure-${{ github.sha }}', 'audit-collector-pressure-tests.json', 'audit-collector-pressure-metrics.json']) assert(workflow.includes(required), required)
  const source = readFileSync(new URL('../internal/agent/audit/collector_pressure_benchmark_test.go', import.meta.url), 'utf8')
  for (const required of ['New(nil)', '20_000', '10_000', '50_000', 'c.Next(protocol.MaxAuditObservationBytes)', 'sha256.Sum256(wire)', 'l.keys != definition.limit', 'dropped != 2', 'runtime.GC()']) assert(source.includes(required), required)
  assert(!source.includes('.limit ='))
})
