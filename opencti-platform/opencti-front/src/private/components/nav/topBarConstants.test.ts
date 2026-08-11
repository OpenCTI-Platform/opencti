import { describe, expect, it } from 'vitest';
import {
  TOP_BAR_HEIGHT,
  TOP_BAR_HEIGHT_FALLBACK,
  TOP_BAR_SEARCH_MAX_WIDTH,
  TOP_BAR_SEARCH_MIN_WIDTH,
} from './topBarConstants';

describe('top bar geometry', () => {
  it('bounds the search window at the cross-product values', () => {
    expect(TOP_BAR_SEARCH_MIN_WIDTH).toBe(200);
    expect(TOP_BAR_SEARCH_MAX_WIDTH).toBe(500);
  });

  it('derives the height from the library custom property, never a bare literal', () => {
    expect(TOP_BAR_HEIGHT).toBe(`var(--fds-header-height, ${TOP_BAR_HEIGHT_FALLBACK}px)`);
    expect(TOP_BAR_HEIGHT).toMatch(/^var\(--fds-header-height,/);
  });
});
