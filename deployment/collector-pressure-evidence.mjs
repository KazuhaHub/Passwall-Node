import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const pkg = 'github.com/KazuhaHub/passwall-node/v4/internal/agent/audit'
const root = 'TestNativeCollectorPressure'
const require = value => { if (!value) throw new Error('Collector pressure evidence invalid; private content withheld') }
const fields = (value, names) => require(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name)))
const count = value => Number.isSafeInteger(value) && value >= 0

export function sanitizeCollectorPressureResults(input) {
  require(typeof input === 'string' && Buffer.byteLength(input) <= 128 * 1024)
  return input.split(/\r?\n/).filter(line => line.trim()).map(line => {
    const event = JSON.parse(line)
    if (event.Action === 'output') return ''
    require(['start', 'run', 'pass', 'fail', 'skip', 'pause', 'cont'].includes(event.Action))
    return JSON.stringify({ Action: event.Action, Package: event.Package === pkg ? pkg : '[other package]',
      ...(Object.hasOwn(event, 'Test') ? { Test: event.Test === root ? root : '[unknown test]' } : {}),
      ...(Number.isFinite(event.Elapsed) && event.Elapsed >= 0 ? { Elapsed: event.Elapsed } : {}),
    })
  }).filter(Boolean).join('\n') + '\n'
}

export function checkCollectorPressureMetrics(input) {
  require(typeof input === 'string' && Buffer.byteLength(input) <= 16 * 1024)
  const value = JSON.parse(input)
  fields(value, ['schema_version', 'iterations', 'total_keys', 'pending_count', 'pending_bytes', 'retained_heap_bytes', 'sampled_peak_heap_bytes', 'lanes'])
  require(value.schema_version === 1 && value.iterations === 1 && value.total_keys === 90000 && value.pending_count === 4)
  require(['pending_bytes', 'retained_heap_bytes', 'sampled_peak_heap_bytes'].every(name => count(value[name]) && value[name] > 0))
  require(value.sampled_peak_heap_bytes >= value.retained_heap_bytes)
  require(Array.isArray(value.lanes) && value.lanes.length === 4)
  const limits = { block: 20000, observe: 10000, trial: 10000, usage: 50000 }
  const seen = new Set()
  let keys = 0, bytes = 0
  for (const lane of value.lanes) {
    fields(lane, ['kind', 'key_limit', 'keys', 'pending_rows', 'pending_bytes', 'dropped_events', 'unmatched', 'slots', 'anonymous_rows', 'identified_rows'])
    require(Object.hasOwn(limits, lane.kind) && !seen.has(lane.kind)); seen.add(lane.kind)
    require(Object.entries(lane).every(([name, value]) => name === 'kind' || count(value)))
    require(lane.key_limit === limits[lane.kind] && lane.keys === lane.key_limit)
    require(lane.pending_rows > 0 && lane.pending_rows <= (lane.kind === 'usage' ? 8192 : 4096))
    require(lane.pending_bytes > 0 && lane.pending_bytes <= 1048576)
    require(lane.dropped_events === 2 && lane.unmatched === 0 && lane.slots === (lane.kind === 'block' ? 4 : 1))
    require(lane.anonymous_rows + lane.identified_rows === lane.pending_rows)
    require(lane.kind === 'trial' ? lane.anonymous_rows === lane.pending_rows : lane.identified_rows === lane.pending_rows)
    keys += lane.keys; bytes += lane.pending_bytes
  }
  require(keys === value.total_keys && bytes === value.pending_bytes && bytes <= 4 * 1048576)
  return { keys, pending_count: 4, pending_bytes: bytes, retained_heap_bytes: value.retained_heap_bytes, sampled_peak_heap_bytes: value.sampled_peak_heap_bytes }
}

export function checkCollectorPressureEvidence(results, metrics) {
  require(typeof results === 'string' && Buffer.byteLength(results) <= 128 * 1024)
  let runs = 0, passes = 0, packages = 0, starts = 0
  for (const line of results.split(/\r?\n/).filter(line => line.trim())) {
    const event = JSON.parse(line)
    require(packages === 0 && event && typeof event === 'object' && Object.keys(event).every(key => ['Action', 'Package', 'Test', 'Elapsed'].includes(key)))
    require(event.Package === pkg && ['start', 'run', 'pass'].includes(event.Action))
    require(event.Test === undefined || event.Test === root)
    require(event.Elapsed === undefined || Number.isFinite(event.Elapsed) && event.Elapsed >= 0)
    if (event.Action === 'run') { require(event.Test === root); runs++ }
    if (event.Action === 'pass' && event.Test === root) { require(runs === 1); passes++ }
    if (event.Action === 'pass' && event.Test === undefined) { require(passes === 1); packages++ }
    if (event.Action === 'start') { require(event.Test === undefined && runs === 0 && starts === 0); starts++ }
  }
  require(runs === 1 && passes === 1 && packages === 1)
  return checkCollectorPressureMetrics(metrics)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv[2] === 'sanitize') process.stdout.write(sanitizeCollectorPressureResults(readFileSync(0, 'utf8')))
    else {
      checkCollectorPressureEvidence(readFileSync(process.argv[2], 'utf8'), readFileSync(process.argv[3], 'utf8'))
      console.log('Four collectors full with four frozen pending subtrees; limits and retention memory measured')
    }
  } catch {
    console.error('Collector pressure evidence failed; private content withheld')
    process.exitCode = 1
  }
}
