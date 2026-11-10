import { describe, expect, it } from 'vitest';
import { allMenuEntries, capabilitiesOf } from './menuEntries';

describe('allMenuEntries', () => {
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

  it('matches a single page, and denies (empty list) an unknown path', () => {
    expect(capabilitiesOf('/dashboard/data/processing/tasks')).toEqual(['KNOWLEDGE_KNUPDATE']);
    expect(capabilitiesOf('/dashboard/nope')).toEqual([]);
  });
});
