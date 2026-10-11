import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { summarizeWindowsModule } from './windows-module-evidence.mjs'

const pkg = 'github.com/KazuhaHub/passwall-node/v4/internal/agent'
const inventory = `${pkg} test\ngithub.com/KazuhaHub/passwall-node/v4/internal/version none\n`
const encode = events => events.map(event => JSON.stringify(event)).join('\n')
const events = () => [
  { Action: 'run', Package: pkg, Test: 'TestReport' },
  { Action: 'run', Package: pkg, Test: 'TestReport/private-host-secret' },
  { Action: 'pass', Package: pkg, Test: 'TestReport/private-host-secret' },
  { Action: 'pass', Package: pkg, Test: 'TestReport' },
  { Action: 'pass', Package: pkg },
]

test('module evidence requires actual uncached package and top-level execution', () => {
  assert.equal(summarizeWindowsModule(inventory, encode(events()), 0).status, 'passed')
  for (const values of [[], events().slice(0, -1), events().filter(event => event.Action !== 'run'), [...events(), events()[0]], [...events(), { Action: 'fail', Package: pkg, Test: 'TestReport/private' }], [...events(), { Action: 'fail', Package: 'foreign' }], [...events(), { Action: 'output', Output: 'ok (cached)' }]]) {
    assert.equal(summarizeWindowsModule(inventory, encode(values), 0).status, 'failed')
  }
  assert.equal(summarizeWindowsModule(inventory, encode(events()), 1).status, 'failed')
  assert.equal(summarizeWindowsModule(inventory, 'private unstructured failure', 0).status, 'failed')
  for (const text of ['', `${pkg} none`, `${pkg} test\n${pkg} test`, `${pkg} test extra`]) assert.throws(() => summarizeWindowsModule(text, encode(events()), 0))
})

test('module failure artifacts exclude raw output, dynamic names and arbitrary metadata', () => {
  const values = [...events(), { Action: 'output', Package: pkg, Output: 'credential=private-key secret-address', Environment: 'secret-env' }, { Action: 'fail', Package: pkg, Test: 'TestReport/private-key-secret-address', Output: 'secret-output' }]
  const report = JSON.stringify(summarizeWindowsModule(inventory, encode(values), 1))
  for (const privateText of ['private-key', 'secret-address', 'secret-env', 'secret-output', 'private-host', 'Output', 'Environment']) assert(!report.includes(privateText), privateText)
  assert(report.includes('TestReport'))
  const diagnostic = summarizeWindowsModule(inventory, encode([...events(), { Action: 'output', Output: 'sync private-path-secret: Incorrect function.' }]), 1)
  assert.equal(diagnostic.diagnostics.directory_sync, 1)
  assert(!JSON.stringify(diagnostic).includes('private-path-secret'))
})

test('existing platform skips are counted and cannot hide failed or contradictory tests', () => {
  const skipped = [...events(), { Action: 'run', Package: pkg, Test: 'TestLinuxOnly' }, { Action: 'skip', Package: pkg, Test: 'TestLinuxOnly' }]
  const report = summarizeWindowsModule('\uFEFF' + inventory.replaceAll('\n', '\r\n'), encode(skipped), 0)
  assert.equal(report.status, 'passed')
  assert.equal(report.packages[0].tests.find(test => test.name === 'TestLinuxOnly').skip, 1)
  for (const event of [{ Action: 'pass', Package: pkg, Test: 'TestLinuxOnly' }, { Action: 'skip', Package: pkg }, { Action: 'skip', Package: pkg, Test: 'TestLinuxOnly' }]) assert.equal(summarizeWindowsModule(inventory, encode([...skipped, event]), 0).status, 'failed')
})

test('default fuzz seeds and examples retain their static root without dynamic cases', () => {
  for (const name of ['FuzzControlPlaneTaskClockBounds', 'Example', 'ExampleReport']) {
    const values = [...events(), { Action: 'run', Package: pkg, Test: name }, { Action: 'run', Package: pkg, Test: name + '/private-seed' }, { Action: 'pass', Package: pkg, Test: name + '/private-seed' }, { Action: 'pass', Package: pkg, Test: name }]
    const report = summarizeWindowsModule(inventory, encode(values), 0)
    assert.equal(report.status, 'passed')
    assert(report.packages[0].tests.some(test => test.name === name && test.pass === 1))
    assert(!JSON.stringify(report).includes('private-seed'))
  }
})

test('Windows full-module job runs every package and participates in the verification gate', () => {
  const workflow = readFileSync(new URL('../.github/workflows/test.yml', import.meta.url), 'utf8').replaceAll('\r\n', '\n')
  const job = workflow.slice(workflow.indexOf('  windows-module:'), workflow.indexOf('  verify:'))
  for (const required of ['runs-on: windows-latest', 'go tool compile -V', 'Git/usr/bin', 'go list -f', 'go test -json -count=1 -timeout=12m ./...', '$testExit = $LASTEXITCODE', 'windows-module-evidence.mjs', 'if: always()', 'windows-module-evidence.json']) assert(job.includes(required), required)
  assert(!job.includes('continue-on-error'))
  assert(!job.includes('path: ${{ runner.temp }}/windows-module-raw'))
  assert(workflow.includes('needs: [checks, race, windows-release-cli, windows-deployment, windows-module]'))
  assert(workflow.includes('test "$WINDOWS_MODULE_RESULT" = success'))
})
