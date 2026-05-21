import { describe, expect, it } from 'vitest';
import { getCurrentTab, isPathOverview } from './tabUtils';

describe('getCurrentTab', () => {
  it('returns next segment after the basepath', () => {
    const value = getCurrentTab(
      '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c/knowledge',
      '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c',
    );
    expect(value).toBe('knowledge');
  });

  it('returns an empty string when fullpath equals basepath', () => {
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

describe('isPathOverview', () => {
  const basePath = '/dashboard/threats/threat_actors_group/abc-123';

  it('returns true when path equals basePath', () => {
    expect(isPathOverview(basePath, basePath)).toBe(true);
  });

  it('returns true when path equals basePath/overview', () => {
    expect(isPathOverview(`${basePath}/overview`, basePath)).toBe(true);
  });

  it('returns false for other sub-paths', () => {
    expect(isPathOverview(`${basePath}/knowledge`, basePath)).toBe(false);
    expect(isPathOverview(`${basePath}/content`, basePath)).toBe(false);
    expect(isPathOverview(`${basePath}/files`, basePath)).toBe(false);
  });
});
