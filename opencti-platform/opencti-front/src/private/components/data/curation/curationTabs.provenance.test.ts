import { describe, expect, it } from 'vitest';
import { CURATION_TABS, grantedCurationTabs } from './curationTabs';
import type { ModuleHelper } from '../../../../utils/platformModulesHelper';

const modules = (provenanceEnabled: boolean) => ({ isProvenanceEnabled: () => provenanceEnabled }) as ModuleHelper;

describe('Curation hub - provenance tabs', () => {
  it('registers Conflicts before Stale knowledge', () => {
    const paths = CURATION_TABS.map((tab) => tab.path);
    expect(paths).toContain('conflicts');
    expect(paths).toContain('stale-knowledge');
    expect(paths.indexOf('conflicts')).toBeLessThan(paths.indexOf('stale-knowledge'));
    expect(CURATION_TABS.find((tab) => tab.path === 'conflicts')?.label).toEqual('Conflicts');
    expect(CURATION_TABS.find((tab) => tab.path === 'stale-knowledge')?.label).toEqual('Stale knowledge');
  });

  it('counts the pending work of both tabs on their tab and on the Curation menu entry', () => {
    expect(CURATION_TABS.find((tab) => tab.path === 'conflicts')?.useBadgeCount).toBeTypeOf('function');
    expect(CURATION_TABS.find((tab) => tab.path === 'stale-knowledge')?.useBadgeCount).toBeTypeOf('function');
  });

  it('drops both tabs, and so their badge queries, while provenance is disabled on the platform', () => {
    const enabled = grantedCurationTabs(CURATION_TABS, () => true, modules(true)).map((tab) => tab.path);
    expect(enabled).toEqual(expect.arrayContaining(['conflicts', 'stale-knowledge']));
    const disabled = grantedCurationTabs(CURATION_TABS, () => true, modules(false)).map((tab) => tab.path);
    expect(disabled).not.toContain('conflicts');
    expect(disabled).not.toContain('stale-knowledge');
  });
});
