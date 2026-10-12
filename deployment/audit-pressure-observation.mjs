const require = value => { if (!value) throw new Error('Audit observation invalid; private content withheld') }
const fields = (value, names) => require(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join() === [...names].sort().join())
const count = value => Number.isSafeInteger(value) && value >= 0

// Ignore the rest of the journal; never forward private core/control lines.
export function readAuditPressureObservation(line) {
  require(typeof line === 'string' && Buffer.byteLength(line) <= 16 * 1024)
  const match = /^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\.\d{6} \[Info\] passwall-node: audit_pressure=(\{[^\r\n]*\})\r?\n?$/.exec(line)
  if (!match) return undefined
  let value
  try { value = JSON.parse(match[1]) } catch { require(false) }
  fields(value, ['schema_version', 'go_heap_alloc_bytes', 'go_heap_inuse_bytes', 'go_heap_objects', 'go_goroutines', 'lanes'])
  require(value.schema_version === 1 && ['go_heap_alloc_bytes', 'go_heap_inuse_bytes', 'go_heap_objects', 'go_goroutines'].every(k => count(value[k]) && value[k] > 0))
  require(value.go_heap_inuse_bytes >= value.go_heap_alloc_bytes)
  require(Array.isArray(value.lanes) && value.lanes.length === 4)
  for (const [i, lane] of value.lanes.entries()) {
    fields(lane, ['kind', 'keys', 'key_limit', 'hours', 'pending', 'pending_rows', 'pending_bytes', 'retained_dropped_events', 'retained_unmatched_events'])
    require(lane.kind === ['block', 'observe', 'trial', 'usage'][i] && lane.key_limit === [20000, 10000, 10000, 50000][i])
    require(Object.entries(lane).filter(([k]) => k !== 'kind').every(([, v]) => count(v)))
    require(lane.keys <= lane.key_limit && lane.hours <= 50 && lane.pending <= 1 && lane.pending_bytes <= 1024 * 1024)
    require(lane.pending_rows <= (i === 3 ? 8192 : 4096))
    require(lane.pending ? lane.pending_bytes > 0 : lane.pending_bytes === 0 && lane.pending_rows === 0)
  }
  return value
}
