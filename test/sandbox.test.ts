/**
 * sandbox.test.ts
 *
 * Pure-logic tests for the file-isolation sandbox (bubblewrap) arg builder and
 * the per-CLI config-scoping helper. No bwrap/network — just the argv shape and
 * the scrub contract.
 */
import { describe, it, expect } from 'vitest';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync, existsSync, writeFileSync, symlinkSync } from 'node:fs';
import { buildSandboxArgs, seedScopedConfig, buildRelayHostArgs, prepareSandbox, type SandboxPlan } from '../src/adapters/backend/sandbox.js';

const tmp = () => mkdtempSync(join(tmpdir(), 'sbx-'));

function plan(over: Partial<SandboxPlan> = {}): SandboxPlan {
  return {
    workDir: '/data/sandboxes/s1/work',
    projectMount: '/home/u/proj',
    scopedHome: '/data/sandboxes/s1/home',
    outbox: '/data/sandboxes/s1/outbox',
    toolchainRo: ['/opt/node'],
    net: true,
    ...over,
  };
}

/** Find the value bwrap would mount at `dest` for a given bind flag. */
function bindDest(args: string[], flag: string, src: string): string | undefined {
  for (let i = 0; i < args.length - 2; i++) {
    if (args[i] === flag && args[i + 1] === src) return args[i + 2];
  }
  return undefined;
}

describe('buildSandboxArgs', () => {
  it('masks the real home with the scoped home', () => {
    const a = buildSandboxArgs(plan());
    expect(bindDest(a, '--bind', '/data/sandboxes/s1/home')).toBe(homedir());
  });

  it('mounts the clone AT projectMount (not at its own host path)', () => {
    const a = buildSandboxArgs(plan());
    // clone host path → projectMount
    expect(bindDest(a, '--bind', '/data/sandboxes/s1/work')).toBe('/home/u/proj');
    // and chdir is the mount target, so the CLI's -C/cwd args resolve
    const ci = a.indexOf('--chdir');
    expect(a[ci + 1]).toBe('/home/u/proj');
  });

  it('binds the outbox at its own path and re-exposes toolchain read-only', () => {
    const a = buildSandboxArgs(plan());
    expect(bindDest(a, '--bind', '/data/sandboxes/s1/outbox')).toBe('/data/sandboxes/s1/outbox');
    expect(bindDest(a, '--ro-bind-try', '/opt/node')).toBe('/opt/node');
  });

  it('keeps the network by default and drops it when net=false', () => {
    expect(buildSandboxArgs(plan({ net: true }))).not.toContain('--unshare-net');
    expect(buildSandboxArgs(plan({ net: false }))).toContain('--unshare-net');
  });

  it('always isolates user/pid/ipc namespaces', () => {
    const a = buildSandboxArgs(plan());
    for (const flag of ['--unshare-user', '--unshare-pid', '--unshare-ipc']) {
      expect(a).toContain(flag);
    }
  });
});

describe('seedScopedConfig', () => {
  it('returns false for a CLI with no persistent config', () => {
    const home = mkdtempSync(join(tmpdir(), 'sbx-'));
    expect(seedScopedConfig('hermes', home)).toBe(false);
  });

  it('creates the scoped config dir for a known CLI (codex)', () => {
    const home = mkdtempSync(join(tmpdir(), 'sbx-'));
    expect(seedScopedConfig('codex', home)).toBe(true);
    // The de-identified ~/.codex is materialised even if the host has nothing to copy.
    expect(existsSync(join(home, '.codex'))).toBe(true);
  });
});

// ── buildRelayHostArgs: the security boundary for the outbox send relay ──────
// Regression for the "sandbox makes host read an arbitrary path" confused-deputy
// blocker: the watcher must NEVER honor raw argv or paths outside the outbox.
describe('buildRelayHostArgs', () => {
  const SID = 'sess-123';

  it('accepts an outbox-resident content file + attachment + allowlisted flags, and forces session-id', () => {
    const outbox = tmp();
    writeFileSync(join(outbox, 'c.content'), 'hi');
    writeFileSync(join(outbox, 'a.png'), 'png');
    const r = buildRelayHostArgs(
      { contentFile: 'c.content', attachments: ['a.png'], flags: ['--mention-back', '--mention', 'ou:X'] },
      outbox, SID,
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.hostArgs).toContain('--mention-back');
    expect(r.hostArgs).toEqual(expect.arrayContaining(['--mention', 'ou:X']));
    expect(r.hostArgs).toEqual(expect.arrayContaining(['--content-file', join(outbox, 'c.content')]));
    expect(r.hostArgs).toEqual(expect.arrayContaining(['--files', join(outbox, 'a.png')]));
    // session-id is FORCED to the worker's value, last
    expect(r.hostArgs.slice(-2)).toEqual(['--session-id', SID]);
  });

  it('rejects the raw-hostArgs exploit (path-bearing flag is not allowlisted)', () => {
    const outbox = tmp();
    writeFileSync(join(outbox, 'c.content'), 'x');
    // the old exploit: try to make the host read bots.json
    const r = buildRelayHostArgs(
      { contentFile: 'c.content', flags: ['--content-file', '/root/.botmux/bots.json'] },
      outbox, SID,
    );
    expect(r.ok).toBe(false);
  });

  it('rejects a sandbox-supplied --session-id (cannot target another session)', () => {
    const outbox = tmp();
    writeFileSync(join(outbox, 'c.content'), 'x');
    const r = buildRelayHostArgs({ contentFile: 'c.content', flags: ['--session-id', 'other'] }, outbox, SID);
    expect(r.ok).toBe(false);
  });

  it('rejects contentFile / attachment paths that escape the outbox', () => {
    const outbox = tmp();
    writeFileSync(join(outbox, 'c.content'), 'x');
    expect(buildRelayHostArgs({ contentFile: '../../etc/passwd' }, outbox, SID).ok).toBe(false);
    expect(buildRelayHostArgs({ contentFile: 'c.content', attachments: ['../secret'] }, outbox, SID).ok).toBe(false);
    expect(buildRelayHostArgs({ contentFile: 'missing' }, outbox, SID).ok).toBe(false);
  });

  it('rejects a symlink inside the outbox that points outside it', () => {
    const outbox = tmp();
    const secretDir = tmp();
    const secret = join(secretDir, 'secret');
    writeFileSync(secret, 'TOP SECRET');
    symlinkSync(secret, join(outbox, 'link.content'));  // sandbox can create symlinks in the bound outbox
    const r = buildRelayHostArgs({ contentFile: 'link.content' }, outbox, SID);
    expect(r.ok).toBe(false);
  });
});

// ── prepareSandbox: the per-bot toggle must actually engage bwrap ────────────
// Regression for the "dashboard sandbox:true never triggers bwrap" blocker:
// prepareSandbox must honor the explicit `enabled` flag, NOT the env var.
describe('prepareSandbox enabled gate', () => {
  it('returns null when not enabled (regardless of env)', () => {
    const r = prepareSandbox({
      enabled: false, cliId: 'codex', sessionId: 's', sourceWorkingDir: tmp(),
      dataDir: tmp(), cliBin: '/bin/true', cliArgs: [],
    });
    expect(r).toBeNull();
  });

  it.skipIf(process.platform !== 'linux')('engages bwrap when enabled=true without BOTMUX_SANDBOX env', () => {
    const src = tmp();
    writeFileSync(join(src, 'file.txt'), 'x');  // a non-git project copied via cp
    const prev = process.env.BOTMUX_SANDBOX;
    delete process.env.BOTMUX_SANDBOX;  // prove env is NOT what enables it
    try {
      const r = prepareSandbox({
        enabled: true, cliId: 'codex', sessionId: 'pb', sourceWorkingDir: src,
        dataDir: tmp(), cliBin: '/bin/true', cliArgs: [],
      });
      expect(r).not.toBeNull();
      expect(r!.bin).toBe('bwrap');
      expect(r!.args).toContain('--');
    } finally {
      if (prev !== undefined) process.env.BOTMUX_SANDBOX = prev;
    }
  });
});
