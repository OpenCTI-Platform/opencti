import { describe, expect, it } from 'vitest';
import { getCurrentTab, getPaddingRight } from './utils';

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

describe('getPaddingRight', () => {
  const basePath = '/dashboard/analyses/reports/a079e1e7-ce97-4528-92f1-64df365d540b';

  it('returns 200 for knowledge path when applyKnowledgePadding is true', () => {
    expect(getPaddingRight(`${basePath}/knowledge`, basePath)).toBe(200);
  });

  it('returns 0 for knowledge path when applyKnowledgePadding is false', () => {
    expect(getPaddingRight(`${basePath}/knowledge`, basePath, false)).toBe(0);
  });

  it('returns 350 for content path (non-mapping)', () => {
    expect(getPaddingRight(`${basePath}/content/editor`, basePath)).toBe(350);
  });

  it('returns 0 for content/mapping path', () => {
    expect(getPaddingRight(`${basePath}/content/mapping`, basePath)).toBe(0);
  });

  it('returns 0 for paths that are neither knowledge nor content', () => {
    expect(getPaddingRight(basePath, basePath)).toBe(0);
    expect(getPaddingRight(`${basePath}/entities`, basePath)).toBe(0);
  });

  it('returns 200 for knowledge sub-paths', () => {
    expect(getPaddingRight(`${basePath}/knowledge/overview?orderAsc=false`, basePath)).toBe(200);
  });
});
