import { describe, expect, it } from 'vitest';
import { CURATION_TABS, grantedCurationTabs } from './curationTabs';
import { CURATION_HEALTH_PATH, CURATION_MERGES_PATH, CURATION_PROPOSALS_PATH } from './curationUtils';

const tabOf = (path: string) => CURATION_TABS.find((tab) => tab.path === path);

describe('Curation hub - knowledge curation tabs', () => {
  it('registers Inbox first, then Merges and Knowledge health after the provenance tabs', () => {
    const paths = CURATION_TABS.map((tab) => tab.path);
    expect(paths[0]).toEqual('inbox');
    expect(paths.indexOf('stale-knowledge')).toBeLessThan(paths.indexOf('merges'));
    expect(paths.indexOf('merges')).toBeLessThan(paths.indexOf('health'));
    expect(tabOf('inbox')?.label).toEqual('Inbox');
    expect(tabOf('merges')?.label).toEqual('Merges');
    expect(tabOf('health')?.label).toEqual('Knowledge health');
  });

  it('serves the routes the rest of the platform links to', () => {
    expect(`/dashboard/data/curation/${tabOf('inbox')?.path}`).toEqual(CURATION_PROPOSALS_PATH);
    expect(`/dashboard/data/curation/${tabOf('merges')?.path}`).toEqual(CURATION_MERGES_PATH);
    expect(`/dashboard/data/curation/${tabOf('health')?.path}`).toEqual(CURATION_HEALTH_PATH);
  });

  it('counts the proposals waiting in the Inbox only', () => {
    expect(tabOf('inbox')?.useBadgeCount).toBeDefined();
    expect(tabOf('merges')?.useBadgeCount).toBeUndefined();
    expect(tabOf('health')?.useBadgeCount).toBeUndefined();
  });

  it('lists the curation tabs only for a user who can read knowledge', () => {
    const curationPaths = ['inbox', 'merges', 'health'];
    const withoutKnowledge = grantedCurationTabs(CURATION_TABS, (needs) => !needs.includes('KNOWLEDGE'));
    expect(withoutKnowledge.map((tab) => tab.path).filter((path) => curationPaths.includes(path))).toEqual([]);
    const withKnowledge = grantedCurationTabs(CURATION_TABS, () => true);
    expect(withKnowledge.map((tab) => tab.path)).toEqual(expect.arrayContaining(curationPaths));
  });
});
