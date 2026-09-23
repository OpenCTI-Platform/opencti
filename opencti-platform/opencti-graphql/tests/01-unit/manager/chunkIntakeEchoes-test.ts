import { describe, expect, it } from 'vitest';
import { isEchoId, splitEchoIds } from '../../../src/manager/chunkIntakeEchoes';

describe('chunk intake echo ids', () => {
  it('recognizes an echo id and nothing else', () => {
    expect(isEchoId('echo--7230c3d9-f7d0-4b7e-8d00-cbe2a7d664a6')).toBe(true);
    expect(isEchoId('identity--1e9eb117-0292-5559-92a3-53422431df30')).toBe(false);
    expect(isEchoId('')).toBe(false);
    expect(isEchoId(undefined)).toBe(false);
    expect(isEchoId(42)).toBe(false);
  });

  it('splits a missing list into resolvable ids and echoes', () => {
    const { resolvable, echoes } = splitEchoIds([
      'identity--1e9eb117-0292-5559-92a3-53422431df30',
      'echo--e40189fa-c48a-48b2-9e68-0f21de6c6477',
      'label--0d1c5a1e-6f4f-4d8b-9a3d-5b2f7c1e8a10',
    ]);
    expect(resolvable).toEqual(['identity--1e9eb117-0292-5559-92a3-53422431df30', 'label--0d1c5a1e-6f4f-4d8b-9a3d-5b2f7c1e8a10']);
    expect(echoes).toEqual(['echo--e40189fa-c48a-48b2-9e68-0f21de6c6477']);
  });

  it('keeps a list without echoes intact', () => {
    const { resolvable, echoes } = splitEchoIds(['identity--a', 'identity--b']);
    expect(resolvable).toEqual(['identity--a', 'identity--b']);
    expect(echoes).toEqual([]);
  });
});
