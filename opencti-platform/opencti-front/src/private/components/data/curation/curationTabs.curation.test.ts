import { lazy } from 'react';
import { describe, expect, it } from 'vitest';
import { CURATION_TABS, grantedCurationTabs } from './curationTabs';
import { CURATION_HEALTH_PATH, CURATION_MERGES_PATH, CURATION_PROPOSALS_PATH } from './curationUtils';

const ROUTE_SEGMENT = /^[a-z][a-z0-9_-]*$/;

const tabOf = (path: string) => CURATION_TABS.find((tab) => tab.path === path);

describe('Curation hub - knowledge curation tabs', () => {
  it('registers Inbox first, then Merges, then Knowledge health', () => {
    const paths = CURATION_TABS.map((tab) => tab.path);
    expect(paths[0]).toEqual('inbox');
    expect(paths.indexOf('merges')).toBeGreaterThan(paths.indexOf('inbox'));
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

describe('CURATION_TABS registry', () => {
  it('gives every tab a unique route segment', () => {
    const paths = CURATION_TABS.map((tab) => tab.path);
    expect(new Set(paths).size).toEqual(paths.length);
  });

  it('gives every tab its own position, in ascending order', () => {
    const orders = CURATION_TABS.map((tab) => tab.order);
    expect(new Set(orders).size).toEqual(orders.length);
    expect(orders).toEqual([...orders].sort((a, b) => a - b));
  });

  it('uses lowercase route segments, as the rest of the dashboard does', () => {
    CURATION_TABS.forEach((tab) => expect(tab.path).toMatch(ROUTE_SEGMENT));
  });

  it('labels every tab with a sentence-case source string', () => {
    CURATION_TABS.forEach((tab) => {
      expect(tab.label.trim()).not.toEqual('');
      expect(tab.label[0]).toEqual(tab.label[0].toUpperCase());
    });
  });

  it('drops a tab the user is not granted, and keeps a tab that needs nothing', () => {
    const lazyNothing = lazy(async () => ({ default: () => null }));
    const tabs = [
      { order: 10, path: 'inbox', label: 'Inbox', needs: ['KNOWLEDGE_KNUPDATE_KNMERGE'], component: lazyNothing },
      { order: 50, path: 'health', label: 'Knowledge health', component: lazyNothing },
    ];
    expect(grantedCurationTabs(tabs, (needs) => needs.includes('KNOWLEDGE')).map((tab) => tab.path)).toEqual(['health']);
  });
});
