import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync } from 'node:fs'
import { processReplayTests, summarizeWindowsProcessReplay } from './windows-process-evidence.mjs'

const pkg = 'github.com/KazuhaHub/passwall-node/v4/internal/core/process'
const events = () => [...Array.from({ length: 10 }, () => processReplayTests.flatMap(Test => [{ Action: 'run', Package: pkg, Test }, { Action: 'pass', Package: pkg, Test }])).flat(), { Action: 'pass', Package: pkg }]
const encode = values => values.map(value => JSON.stringify(value)).join('\n')

test('process replay requires ten actual passes for each source-owned rollback root', () => {
  assert.equal(summarizeWindowsProcessReplay(encode(events()), 0).status, 'passed')
  for (const values of [[], events().slice(1), events().slice(0, -1), [...events(), events()[0]], [...events(), { Action: 'fail', Package: pkg, Test: processReplayTests[0] }], [...events(), { Action: 'skip', Package: pkg }], [...events(), { Action: 'pass', Package: pkg, Test: 'ForeignRoot' }], [...events(), { Action: 'pass', Package: 'foreign' }], [...events(), { Action: 'output', Output: 'ok (cached)' }]]) assert.equal(summarizeWindowsProcessReplay(encode(values), 0).status, 'failed')
  assert.equal(summarizeWindowsProcessReplay(encode(events()), 1).status, 'failed')
  assert.equal(summarizeWindowsProcessReplay('raw private output', 0).status, 'failed')
})

test('process replay discards private output and records only fixed failure classes', () => {
  const values = [...events(), { Action: 'output', Output: 'apply error = <nil> private-path', Environment: 'private-env' }, { Action: 'output', Output: 'rollback status = private-configuration-and-digest' }]
  const report = summarizeWindowsProcessReplay(encode(values), 1)
  assert.equal(report.diagnostics.startup_accepted, 1)
  assert.equal(report.diagnostics.rollback_status, 1)
  for (const text of ['private-path', 'private-env', 'private-configuration', 'Output', 'Environment']) assert(!JSON.stringify(report).includes(text))
})

test('Windows job retains the full module and adds bounded replay with private evidence', () => {
  const workflow = readFileSync(new URL('../.github/workflows/test.yml', import.meta.url), 'utf8').replaceAll('\r\n', '\n')
  const job = workflow.slice(workflow.indexOf('  windows-module:'), workflow.indexOf('  verify:'))
  assert(job.includes('go test -json -count=1 -timeout=12m ./...'))
  assert(job.includes('go test -json -count=10 -timeout=4m ./internal/core/process'))
  for (const name of processReplayTests) assert(job.includes(name))
  assert(job.includes('windows-process-evidence.mjs'))
  assert(!job.includes('path: ${{ runner.temp }}/windows-process-raw'))
  assert(!job.includes('continue-on-error'))
})
