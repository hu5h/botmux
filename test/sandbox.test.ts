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
import { mkdtempSync, existsSync } from 'node:fs';
import { buildSandboxArgs, seedScopedConfig, type SandboxPlan } from '../src/adapters/backend/sandbox.js';

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
