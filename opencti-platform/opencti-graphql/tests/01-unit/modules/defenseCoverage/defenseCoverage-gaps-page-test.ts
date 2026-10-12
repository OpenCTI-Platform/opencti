import { describe, expect, it } from 'vitest';
import { findDefenseGaps, gapsPageWindow, hasNextGapsPage } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

// The cursor of a gap designates its position in the backlog
const cursorOf = (offset: number | string) => Buffer.from(`defense-gap:${offset}`, 'utf-8').toString('base64');
const TOO_DEEP = 'A defense gaps page cannot start after the first 10000 gaps: narrow the filters';

describe('Defense gaps pages', () => {
  it('should start a page after its cursor and bound its size', () => {
    expect(gapsPageWindow(null, null)).toEqual({ start: 0, first: 50 });
    expect(gapsPageWindow(cursorOf(49), 5000)).toEqual({ start: 50, first: 500 });
  });

  it('should refuse a cursor beyond the first 10000 gaps', () => {
    expect(gapsPageWindow(cursorOf(9998), 50)).toEqual({ start: 9999, first: 50 });
    expect(() => gapsPageWindow(cursorOf(9999), 50)).toThrow(TOO_DEEP);
    expect(() => gapsPageWindow(cursorOf(Number.MAX_SAFE_INTEGER - 1), 50)).toThrow(TOO_DEEP);
    expect(() => gapsPageWindow(cursorOf('1e+30'), 50)).toThrow(TOO_DEEP);
  });

  it('should refuse a malformed cursor', () => {
    expect(() => gapsPageWindow(Buffer.from('other:1', 'utf-8').toString('base64'), 50)).toThrow('Invalid defense gaps cursor');
    expect(() => gapsPageWindow(cursorOf(-2), 50)).toThrow('Invalid defense gaps cursor');
  });

  it('should offer no page after the first 10000 gaps, whatever the number of gaps', () => {
    expect(hasNextGapsPage(0, 50, 120)).toEqual(true);
    expect(hasNextGapsPage(100, 50, 120)).toEqual(false);
    expect(hasNextGapsPage(9900, 50, 50000)).toEqual(true);
    expect(hasNextGapsPage(9950, 50, 50000)).toEqual(false);
  });

  it('should refuse a deep cursor of the backlog before reading anything', async () => {
    await expect(findDefenseGaps({} as AuthContext, {} as AuthUser, { after: cursorOf(20000) })).rejects.toThrow(TOO_DEEP);
  });
});
