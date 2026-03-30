import { describe, expect, it } from 'vitest';
import { getCurrentTab } from './utils';

describe('getCurrentTab', () => {
  it('returns next segment after the basepath', () => {
    const value = getCurrentTab(
      '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c/knowledge',
      '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c',
    );
    expect(value).toBe('knowledge');
  });

  it('returns false when fullpath equals basepath', () => {
    const value = getCurrentTab(
      '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c',
      '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c',
    );
    expect(value).toBe('');
  });

  it('returns next segment after the basepath even when there are more', () => {
    const value = getCurrentTab(
      '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c/knowledge/or/something/else',
      '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c',
    );
    expect(value).toBe('knowledge');
  });
});
