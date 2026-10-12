import { readFileSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const pkg = 'github.com/KazuhaHub/passwall-node/v4/internal/core/process'
export const processReplayTests = Object.freeze([
  'TestSupervisorRollsBackCandidateThatExitsDuringStartup',
  'TestSupervisorSwitchesVersionAndRollsBackBinaryIdentity',
  'TestSupervisorSwitchesEngineAndRollsBackDeploymentIdentity',
])

// Static names and counts only; no child output, arguments or identities.
export function summarizeWindowsProcessReplay(input, exitCode) {
  if (typeof input !== 'string' || input.length > 32 << 20 || !Number.isInteger(exitCode) || exitCode < 0 || exitCode > 255) throw new Error('Invalid process evidence input')
  const tests = new Map(processReplayTests.map(name => [name, { name, run: 0, pass: 0, fail: 0, skip: 0 }]))
  let invalid = false, cached = false, packagePass = 0, packageFail = 0
  const diagnostics = { startup_accepted: 0, rollback_status: 0 }
  for (const line of input.replace(/^\uFEFF/, '').split(/\r?\n/).filter(line => line.trim())) {
    let event
    try { event = JSON.parse(line) } catch { invalid = true; continue }
    if (!event || typeof event !== 'object' || Array.isArray(event)) { invalid = true; continue }
    if (event.Action === 'output') {
      if (typeof event.Output === 'string') {
        if (event.Output.includes('(cached)')) cached = true
        if (/(?:apply|failed switch) error = <nil>/.test(event.Output)) diagnostics.startup_accepted++
        if (/rollback status =|failed switch did not restore prior identity:/.test(event.Output)) diagnostics.rollback_status++
      }
      continue
    }
    if (!['run', 'pass', 'fail', 'skip'].includes(event.Action)) continue
    if (event.Package !== pkg) { invalid = true; continue }
    if (event.Test === undefined) {
      if (event.Action === 'pass') packagePass++
      else if (event.Action === 'fail') packageFail++
      else invalid = true
      continue
    }
    const test = tests.get(event.Test)
    if (!test) { invalid = true; continue }
    test[event.Action]++
  }
  const passed = exitCode === 0 && !invalid && !cached && packagePass === 1 && packageFail === 0 && [...tests.values()].every(test => test.run === 10 && test.pass === 10 && test.fail === 0 && test.skip === 0)
  return { schema: 1, status: passed ? 'passed' : 'failed', exitCode, invalid, cached, diagnostics, packagePass, packageFail, tests: [...tests.values()] }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [input, code, output] = process.argv.slice(2)
  try {
    if (!input || !output || process.argv.length !== 5 || !/^\d{1,3}$/.test(code)) throw new Error('Invalid arguments')
    const report = summarizeWindowsProcessReplay(readFileSync(input, 'utf8'), Number(code))
    writeFileSync(output, JSON.stringify(report) + '\n', { mode: 0o600 })
    console.log(`Windows process replay: ${report.status}`)
    process.exitCode = report.status === 'passed' ? 0 : 1
  } catch {
    console.error('Invalid process evidence; private output withheld')
    process.exitCode = 1
  }
}
