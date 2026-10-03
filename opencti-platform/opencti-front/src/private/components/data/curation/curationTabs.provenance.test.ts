import { describe, expect, it } from 'vitest';
import { CURATION_TABS } from './curationTabs';

describe('Curation hub - provenance tabs', () => {
  it('registers Conflicts before Stale knowledge', () => {
    const paths = CURATION_TABS.map((tab) => tab.path);
    expect(paths).toContain('conflicts');
    expect(paths).toContain('stale-knowledge');
    expect(paths.indexOf('conflicts')).toBeLessThan(paths.indexOf('stale-knowledge'));
    expect(CURATION_TABS.find((tab) => tab.path === 'conflicts')?.label).toEqual('Conflicts');
    expect(CURATION_TABS.find((tab) => tab.path === 'stale-knowledge')?.label).toEqual('Stale knowledge');
  });
});
