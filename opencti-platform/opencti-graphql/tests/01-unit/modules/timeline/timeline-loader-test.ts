import { describe, expect, it } from 'vitest';
import { capTimelineRead } from '../../../../src/modules/timeline/timeline-loader';

describe('Timeline derivation input bounds', () => {
  it('should keep a family within its bound untouched and not report a truncation', () => {
    const bounds = { truncated: false };
    expect(capTimelineRead(bounds, [1, 2, 3], 3)).toEqual([1, 2, 3]);
    expect(capTimelineRead(bounds, [], 3)).toEqual([]);
    expect(bounds.truncated).toBe(false);
  });

  it('should cap a family read one item past its bound and report the truncation', () => {
    const bounds = { truncated: false };
    expect(capTimelineRead(bounds, [1, 2, 3, 4], 3)).toEqual([1, 2, 3]);
    expect(bounds.truncated).toBe(true);
  });

  it('should keep the truncation reported by an earlier family', () => {
    const bounds = { truncated: false };
    capTimelineRead(bounds, ['a', 'b'], 1);
    expect(capTimelineRead(bounds, ['c'], 5)).toEqual(['c']);
    expect(bounds.truncated).toBe(true);
  });
});
