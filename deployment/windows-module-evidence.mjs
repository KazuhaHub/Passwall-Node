import { readFileSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const modulePath = 'github.com/KazuhaHub/passwall-node/v4'
const packagePattern = /^github\.com\/KazuhaHub\/passwall-node\/v4(?:\/[A-Za-z0-9_-]+)*$/
const testPattern = /^(?:Test|Fuzz)[A-Za-z0-9_]+$|^Example[A-Za-z0-9_]*$/
const actions = ['run', 'pass', 'skip', 'fail']
const counts = () => ({ run: 0, pass: 0, skip: 0, fail: 0 })
const diagnosticPatterns = {
  directory_sync: /sync .*: (?:Incorrect function|The handle is invalid)/,
  private_mode: /(?:credential|token|lock file|lock) mode =|want (?:0?600|0?700)/,
  private_directory: /directory must be private|directory permissions|directory is not private/,
  process_startup_accepted: /apply error = <nil>/,
  process_rollback_status: /rollback status =/,
}

// Keep source-owned package/top-level test names and counts. Test output,
// dynamic subtest names, timestamps and arbitrary metadata never reach artifacts.
export function summarizeWindowsModule(inventory, input, exitCode) {
  if (typeof inventory !== 'string' || typeof input !== 'string' || inventory.length > 1 << 20 || input.length > 128 << 20 || !Number.isInteger(exitCode) || exitCode < 0 || exitCode > 255) throw new Error('Invalid module evidence input')
  const packages = new Map()
  for (const line of inventory.replace(/^\uFEFF/, '').trim().split(/\r?\n/)) {
    const [name, kind, extra] = line.trim().split(/\s+/)
    if (!packagePattern.test(name) || !['test', 'none'].includes(kind) || extra || packages.has(name)) throw new Error('Invalid module package inventory')
    packages.set(name, { name, tested: kind === 'test', events: counts(), tests: new Map(), failures: 0 })
  }
  if (![...packages.values()].some(p => p.tested) || !packages.has(modulePath + '/internal/agent')) throw new Error('Incomplete module package inventory')
  let invalid = false
  let cached = false
  const diagnostics = Object.fromEntries(Object.keys(diagnosticPatterns).map(name => [name, 0]))
  for (const line of input.replace(/^\uFEFF/, '').split(/\r?\n/).filter(line => line.trim())) {
    let event
    try { event = JSON.parse(line) } catch { invalid = true; continue }
    if (!event || typeof event !== 'object' || Array.isArray(event)) { invalid = true; continue }
    if (event.Action === 'output') {
      if (typeof event.Output === 'string') {
        if (event.Output.includes('(cached)')) cached = true
        for (const [name, pattern] of Object.entries(diagnosticPatterns)) if (pattern.test(event.Output)) diagnostics[name]++
      }
      continue
    }
    if (!actions.includes(event.Action)) continue
    const pkg = packages.get(event.Package)
    if (!pkg) { invalid = true; continue }
    if (event.Action === 'fail') pkg.failures++
    if (event.Test === undefined) { pkg.events[event.Action]++; continue }
    if (typeof event.Test !== 'string') { invalid = true; continue }
    const name = event.Test.split('/')[0]
    if (!testPattern.test(name)) { invalid = true; continue }
    if (event.Test !== name) continue
    if (!pkg.tests.has(name)) pkg.tests.set(name, counts())
    pkg.tests.get(name)[event.Action]++
  }
  const passed = exitCode === 0 && !invalid && !cached && [...packages.values()].every(pkg => {
    if (pkg.failures) return false
    if (!pkg.tested) return true
    return pkg.events.pass === 1 && pkg.events.fail === 0 && pkg.events.skip === 0 && pkg.tests.size > 0 && [...pkg.tests.values()].every(test => test.run === 1 && test.pass + test.skip === 1 && test.fail === 0)
  })
  return {
    schema: 1, status: passed ? 'passed' : 'failed', exitCode, invalid, cached, diagnostics,
    packages: [...packages.values()].map(pkg => ({ name: pkg.name, tested: pkg.tested, events: pkg.events, failures: pkg.failures, tests: [...pkg.tests].map(([name, events]) => ({ name, ...events })) })),
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [inventoryPath, inputPath, code, outputPath] = process.argv.slice(2)
  try {
    if (!inventoryPath || !inputPath || !outputPath || process.argv.length !== 6 || !/^\d{1,3}$/.test(code)) throw new Error('Invalid arguments')
    const report = summarizeWindowsModule(readFileSync(inventoryPath, 'utf8'), readFileSync(inputPath, 'utf8'), Number(code))
    writeFileSync(outputPath, JSON.stringify(report) + '\n', { mode: 0o600 })
    console.log(`Windows module evidence: ${report.status}`)
    process.exitCode = report.status === 'passed' ? 0 : 1
  } catch {
    if (outputPath) writeFileSync(outputPath, JSON.stringify({ schema: 1, status: 'failed', invalid: true }) + '\n', { mode: 0o600 })
    console.error('Windows module evidence rejected; private output withheld')
    process.exitCode = 1
  }
}
