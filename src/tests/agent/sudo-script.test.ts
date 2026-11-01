import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildSudoScript } from '../../main/agent/sudo-script';

describe('buildSudoScript', () => {
  it('validates with sudo -S -v, closes stdin, then runs non-interactive sudo', () => {
    expect(buildSudoScript('sudo apt-get update && sudo apt-get install -y jq')).toBe(
      [
        "sudo -S -p '' -v || exit 1",
        'exec 0</dev/null',
        'sudo -n apt-get update && sudo -n apt-get install -y jq',
      ].join('\n')
    );
  });

  it('leaves words that only contain "sudo" alone', () => {
    expect(buildSudoScript('echo pseudocode sudoers')).toContain('echo pseudocode sudoers');
  });
});

// Runs the generated script under a real /bin/sh with a fake `sudo` on PATH,
// to check that the password never reaches the model-written command.
describe.skipIf(process.platform === 'win32')('buildSudoScript in a real shell', () => {
  const PASSWORD = 'hunter2-secret';
  let binDir: string;

  beforeAll(() => {
    binDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fake-sudo-'));
    const fakeSudo = path.join(binDir, 'sudo');
    // -v: with FAKE_CACHED=1 behaves like cached credentials (does not read
    // stdin); otherwise reads one line and checks it. -n: runs the rest.
    fs.writeFileSync(
      fakeSudo,
      [
        '#!/bin/sh',
        'case "$*" in',
        '  *-v*)',
        '    [ "$FAKE_CACHED" = 1 ] && exit 0',
        '    IFS= read -r pw || exit 1',
        `    [ "$pw" = "${PASSWORD}" ] || exit 1`,
        '    exit 0 ;;',
        '  -n\\ *) shift; exec "$@" ;;',
        '  *) echo "unexpected sudo args: $*" >&2; exit 2 ;;',
        'esac',
        '',
      ].join('\n'),
      { mode: 0o755 }
    );
  });

  afterAll(() => {
    fs.rmSync(binDir, { recursive: true, force: true });
  });

  function run(command: string, env: Record<string, string> = {}) {
    return spawnSync('/bin/sh', ['-c', buildSudoScript(command)], {
      input: `${PASSWORD}\n`,
      env: { ...process.env, ...env, PATH: `${binDir}:${process.env.PATH}` },
      encoding: 'utf8',
    });
  }

  it('runs the command through sudo -n after validating the password', () => {
    const result = run('sudo echo ran-as-root');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('ran-as-root');
  });

  it('does not let another program in the command read the password', () => {
    const result = run('head -n1; cat; sudo echo done');
    expect(result.stdout + result.stderr).not.toContain(PASSWORD);
    expect(result.stdout).toContain('done');
  });

  it('drops the unread password when sudo already had cached credentials', () => {
    const result = run('cat; sudo echo done', { FAKE_CACHED: '1' });
    expect(result.stdout + result.stderr).not.toContain(PASSWORD);
  });

  it('stops before running anything when the password is wrong', () => {
    const result = spawnSync('/bin/sh', ['-c', buildSudoScript('echo should-not-run')], {
      input: 'wrong\n',
      env: { ...process.env, PATH: `${binDir}:${process.env.PATH}` },
      encoding: 'utf8',
    });
    expect(result.status).not.toBe(0);
    expect(result.stdout).not.toContain('should-not-run');
  });
});
