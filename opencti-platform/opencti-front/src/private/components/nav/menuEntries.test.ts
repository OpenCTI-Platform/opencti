import { describe, expect, it } from 'vitest';
import { allMenuEntries, capabilitiesOf, entriesModules } from './menuEntries';

describe('allMenuEntries', () => {
  it('collects every *.entries.ts(x) file: each one must default-export its MenuEntry[]', () => {
    const withoutEntries = Object.entries(entriesModules).filter(([, entries]) => !Array.isArray(entries)).map(([file]) => file);
    expect(withoutEntries).toEqual([]);
  });

  it('declares each page once: the pages search keeps one node per path, so a twin would silently replace the other', () => {
    const paths = allMenuEntries.map(({ path }) => path);
    const duplicates = paths.filter((path, index) => paths.indexOf(path) !== index);
    expect(duplicates).toEqual([]);
  });
});

describe('capabilitiesOf', () => {
  it('is the union of the entries under a section (the old hand-written route guards)', () => {
    expect(capabilitiesOf('/dashboard/settings/vocabularies').sort()).toEqual([
      'SETTINGS_SETCASETEMPLATES',
      'SETTINGS_SETCUSTOMFIELDS',
      'SETTINGS_SETKILLCHAINPHASES',
      'SETTINGS_SETLABELS',
      'SETTINGS_SETSTATUSTEMPLATES',
      'SETTINGS_SETVOCABULARIES',
    ]);
    expect(capabilitiesOf('/dashboard/settings/accesses').sort()).toEqual([
      'SETTINGS_SETACCESSES',
      'SETTINGS_SETAUTH',
      'SETTINGS_SETDISSEMINATION',
      'SETTINGS_SETMARKINGS',
      'VIRTUAL_ORGANIZATION_ADMIN',
    ]);
  });

  it('keeps Roles templates closed to organization admins (they only manage users and organizations)', () => {
    expect(capabilitiesOf('/dashboard/settings/accesses/roles')).toEqual(['SETTINGS_SETACCESSES']);
  });

  it('matches a single page, and denies (empty list) an unknown path', () => {
    expect(capabilitiesOf('/dashboard/data/processing/tasks')).toEqual(['KNOWLEDGE_KNUPDATE']);
    expect(capabilitiesOf('/dashboard/nope')).toEqual([]);
  });
});

describe('route guards', () => {
  // A literal `needs={[...]}` on a route is a second copy of the entry's capabilities: it would silently drift from the
  // left bar and the pages search. Routes must use `capabilitiesOf`, except these (redirects / deliberately narrower).
  const allowed: Record<string, string[]> = {
    '/src/private/components/settings/Root.tsx': ['/experience'], // narrower than the entry: Parameters-only users get a "permission required" dialog
    '/src/private/components/data/Root.tsx': ['/processing'], // not a page: picks where to redirect
  };
  const roots = import.meta.glob<string>(
    ['/src/private/components/settings/Root.tsx', '/src/private/components/settings/{accesses,activity,customization,vocabularies}/Root.tsx', '/src/private/components/data/Root.tsx'],
    { query: '?raw', import: 'default', eager: true },
  );

  it('read their capabilities from the menu entries, not from a copy', () => {
    const literal = Object.entries(roots).flatMap(([file, source]) => source.split('<Route\n').slice(1)
      .filter((route) => /needs=\{\[/.test(route))
      .map((route) => route.match(/path="([^"]*)"/)?.[1] ?? '')
      .filter((path) => !allowed[file]?.includes(path))
      .map((path) => `${file.split('/components/')[1]} ${path}`));
    expect(literal).toEqual([]);
  });

  it('checks that it scans the Root files it claims to', () => {
    expect(Object.keys(roots).length).toBe(6);
  });
});
