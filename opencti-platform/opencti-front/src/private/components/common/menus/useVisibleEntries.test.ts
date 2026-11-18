import { beforeEach, describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../../utils/tests/test-render';
import useVisibleEntries from './useVisibleEntries';
import type { MenuEntry } from './menuEntry';

// The user and the platform, as the hook sees them.
let capabilities: string[] = [];
let capabilitiesInDraft: string[] = [];
let draftContext: { id: string } | null = null;
let enabledFlags: string[] = [];
let enterpriseEdition = true;
let trashEnabled = true;
let hiddenEntities: string[] = [];
vi.mock('../../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useAuth')>()),
  default: () => ({
    me: {
      capabilities: capabilities.map((name) => ({ name })),
      capabilitiesInDraft: capabilitiesInDraft.map((name) => ({ name })),
      draftContext,
    },
  }),
}));
vi.mock('../../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (flag: string) => enabledFlags.includes(flag), isTrashEnable: () => trashEnabled }),
}));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => enterpriseEdition }));
vi.mock('../../../../utils/hooks/useEntitySettings', () => ({ useHiddenEntities: () => hiddenEntities }));

const visible = (entries: MenuEntry[]) => testRenderHook(() => useVisibleEntries(entries)).hook.result.current.map(({ path }) => path);

beforeEach(() => {
  capabilities = [];
  capabilitiesInDraft = [];
  draftContext = null;
  enabledFlags = [];
  enterpriseEdition = true;
  trashEnabled = true;
  hiddenEntities = [];
});

describe('Hook: useVisibleEntries', () => {
  describe('draft', () => {
    const entries: MenuEntry[] = [
      { path: '/profile', label: 'Profile', availableInDraft: true },
      { path: '/notifications', label: 'Notifications' },
    ];

    it('keeps every entry outside a draft', () => {
      expect(visible(entries)).toEqual(['/profile', '/notifications']);
    });

    it('in a draft, only keeps the entries that say they are available there', () => {
      draftContext = { id: 'draft-id' };
      expect(visible(entries)).toEqual(['/profile']);
    });
  });

  describe('requiredCapabilities', () => {
    const entries: MenuEntry[] = [
      { path: '/open', label: 'Open' },
      { path: '/any-of', label: 'Any of', requiredCapabilities: ['SETTINGS_SETLABELS', 'SETTINGS_SETMARKINGS'] },
      { path: '/one', label: 'One', requiredCapabilities: ['SETTINGS_SETAUTH'] },
    ];

    it('keeps an entry without any rule for everyone', () => {
      expect(visible(entries)).toEqual(['/open']);
    });

    it('is any-of: one of the capabilities is enough, never all of them', () => {
      capabilities = ['SETTINGS_SETMARKINGS'];
      expect(visible(entries)).toEqual(['/open', '/any-of']);
    });

    it('hides an entry whose capabilities the user does not have', () => {
      capabilities = ['KNOWLEDGE'];
      expect(visible(entries)).toEqual(['/open']);
    });

    it('lets a BYPASS user see every entry', () => {
      capabilities = ['BYPASS'];
      expect(visible(entries)).toEqual(['/open', '/any-of', '/one']);
    });
  });

  describe('capabilitiesInDraft', () => {
    // Drafts page: KNASKIMPORT, or KNUPDATE in the draft (a user who can only work in drafts).
    const entries: MenuEntry[] = [
      { path: '/drafts', label: 'Drafts', requiredCapabilities: ['KNOWLEDGE_KNASKIMPORT'], capabilitiesInDraft: ['KNOWLEDGE_KNUPDATE'] },
    ];

    it('shows the entry to a user who only has the capability in drafts', () => {
      capabilitiesInDraft = ['KNOWLEDGE_KNUPDATE'];
      expect(visible(entries)).toEqual(['/drafts']);
    });

    it('does not take a base capability for a capability in drafts', () => {
      capabilities = ['KNOWLEDGE_KNUPDATE'];
      expect(visible(entries)).toEqual([]);
    });
  });

  describe('requiresEE', () => {
    const entries: MenuEntry[] = [{ path: '/ee', label: 'EE', requiresEE: true }];

    it('shows an Enterprise Edition entry with a licence', () => {
      expect(visible(entries)).toEqual(['/ee']);
    });

    it('hides it without a licence', () => {
      enterpriseEdition = false;
      expect(visible(entries)).toEqual([]);
    });
  });

  describe('featureFlag', () => {
    const entries: MenuEntry[] = [{ path: '/flagged', label: 'Flagged', featureFlag: 'SOME_FLAG' }];

    it('shows an entry whose flag is on', () => {
      enabledFlags = ['SOME_FLAG'];
      expect(visible(entries)).toEqual(['/flagged']);
    });

    it('hides it when the flag is off', () => {
      expect(visible(entries)).toEqual([]);
    });
  });

  describe('platform settings', () => {
    it('hides an entry whose own entity type is hidden, not the others sharing its page', () => {
      const entries: MenuEntry[] = [
        { path: '/observables', label: 'Observables', entityType: 'Stix-Cyber-Observable' },
        { path: '/observables', label: 'IPv4', entityType: 'IPv4-Addr' },
      ];
      hiddenEntities = ['IPv4-Addr'];
      expect(testRenderHook(() => useVisibleEntries(entries)).hook.result.current.map(({ label }) => label)).toEqual(['Observables']);
    });

    it('hides the trash when it is disabled', () => {
      const entries: MenuEntry[] = [{ path: '/dashboard/trash', label: 'Trash' }];
      expect(visible(entries)).toEqual(['/dashboard/trash']);
      trashEnabled = false;
      expect(visible(entries)).toEqual([]);
    });
  });
});
