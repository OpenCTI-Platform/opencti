import { describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../../utils/tests/test-render';
import useVisibleEntries from './useVisibleEntries';
import type { MenuEntry } from './menuEntry';

let draftContext: { id: string } | null = null;
vi.mock('../../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useAuth')>()),
  default: () => ({ me: { capabilities: [{ name: 'BYPASS' }], capabilitiesInDraft: [], draftContext } }),
}));
vi.mock('../../../../utils/hooks/useHelper', () => ({ default: () => ({ isFeatureEnable: () => true }) }));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => true }));

const entries: MenuEntry[] = [
  { path: '/profile', label: 'Profile', availableInDraft: true },
  { path: '/notifications', label: 'Notifications' },
];
const visible = () => testRenderHook(() => useVisibleEntries(entries)).hook.result.current.map(({ path }) => path);

describe('Hook: useVisibleEntries', () => {
  it('keeps every entry outside a draft', () => {
    draftContext = null;
    expect(visible()).toEqual(['/profile', '/notifications']);
  });

  it('in a draft, only keeps the entries that say they are available there', () => {
    draftContext = { id: 'draft-id' };
    expect(visible()).toEqual(['/profile']);
  });
});
