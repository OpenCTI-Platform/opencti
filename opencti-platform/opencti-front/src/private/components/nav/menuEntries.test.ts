import { describe, expect, it } from 'vitest';
import { allMenuEntries, entriesModules, entriesUnder } from './menuEntries';
import type { MenuEntry } from '../common/menus/menuEntry';

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

// What EntryGuard asks the visibility rules about.
describe('entriesUnder', () => {
  const paths = (path: string, options?: { exact?: boolean }) => entriesUnder(path, options).map((entry) => entry.path);

  it('is every page under a section', () => {
    expect(paths('/dashboard/settings/activity')).toEqual([
      '/dashboard/settings/activity/audit',
      '/dashboard/settings/activity/configuration',
      '/dashboard/settings/activity/alerting',
    ]);
  });

  it('is the page itself for a page', () => {
    expect(paths('/dashboard/data/processing/tasks')).toEqual(['/dashboard/data/processing/tasks']);
  });

  it('with `exact`, is only the page, not the pages under it (Parameters heads the Settings pages)', () => {
    expect(paths('/dashboard/settings', { exact: true })).toEqual(['/dashboard/settings']);
    expect(paths('/dashboard/settings').length).toBeGreaterThan(1);
  });

  it('matches whole path segments: a path prefix is not a section', () => {
    expect(paths('/dashboard/settings/access')).toEqual([]);
  });

  it('is empty for an unknown path, which the guard denies', () => {
    expect(paths('/dashboard/nope')).toEqual([]);
  });
});

// Product rules held by the entries data.
describe('entries rules', () => {
  const capabilitiesOf = (path: string) => entriesUnder(path, { exact: true }).flatMap(({ requiredCapabilities }) => requiredCapabilities ?? []);

  it('keeps Roles closed to organization admins (they only manage users and organizations)', () => {
    expect(capabilitiesOf('/dashboard/settings/accesses/roles')).toEqual(['SETTINGS_SETACCESSES']);
  });
});

describe('route guards', () => {
  // A literal `needs={[...]}` on a route is a second copy of the entry's capabilities: it would silently drift from the
  // left bar and the pages search. Routes must use `EntryGuard`, except these (redirects / deliberately narrower).
  const allowed: Record<string, string[]> = {
    '/src/private/components/settings/Root.tsx': ['/experience'], // narrower than the entry: Parameters-only users get a "permission required" dialog
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

describe('route guards coverage', () => {
  // A page declared by an entry but opened by a route without `EntryGuard` would stay reachable by URL when the menus hide it.
  // Only literal `<EntryGuard path="…">` in `Index.tsx` and `**/Root.{tsx,jsx}` is seen: a guard added in another file,
  // or with a computed path, is not counted. Extend the glob or the regex below if you add one there.
  const sources = import.meta.glob<string>(
    ['/src/private/Index.tsx', '/src/private/components/**/Root.{tsx,jsx}'],
    { query: '?raw', import: 'default', eager: true },
  );
  const guards = Object.values(sources).flatMap((source) => [...source.matchAll(/<EntryGuard\s+path="([^"]+)"(\s+exact)?/g)]
    .map(([, path, exact]) => ({ path, exact: !!exact })));
  const guarded = guards.map(({ path }) => path);

  // The rules `useVisibleEntries` applies to an entry (keep in sync). `entityType` is left out: guards ignore hidden types.
  const rules = (entry: MenuEntry) => JSON.stringify([
    [...(entry.requiredCapabilities ?? [])].sort(),
    [...(entry.capabilitiesInDraft ?? [])].sort(),
    !!entry.availableInDraft,
    entry.featureFlag ?? null,
    !!entry.requiresEE,
  ]);
  const openToAll = rules({ path: '', label: '', availableInDraft: true });

  // A page is protected by a guard on its own path, or by a section guard when every page of the section has its rules
  // (a section guard lets in users of any of its pages: one looser than this page would let them in too).
  // A page without any rule needs no guard.
  it('protects every page the entries declare, with its own rules', () => {
    const exposed = allMenuEntries
      .filter((entry) => rules(entry) !== openToAll && !guarded.includes(entry.path))
      .filter((entry) => !guards.some((guard) => !guard.exact
        && entry.path.startsWith(`${guard.path}/`)
        && entriesUnder(guard.path).every((sibling) => rules(sibling) === rules(entry))))
      .map(({ path }) => `${path}: add an EntryGuard on this page (no guard, or only a section guard whose pages have other rules)`);
    expect(exposed).toEqual([]);
  });

  // A typo in a guard path would deny its page to everyone, silently.
  it('guards only paths the entries declare', () => {
    const unknown = guarded.filter((guard) => !allMenuEntries.some(({ path }) => path === guard || path.startsWith(`${guard}/`)));
    expect(unknown).toEqual([]);
  });
});
