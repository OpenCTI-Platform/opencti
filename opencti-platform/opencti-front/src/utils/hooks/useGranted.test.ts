import { DraftContext } from './useDraftContext';
import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import useGranted, { SETTINGS, BYPASS  } from './useGranted';

vi.mock('./useAuth', () => ({ default: vi.fn() }));

import useAuth from './useAuth';
import { RootMe_data$data } from '../../private/__generated__/RootMe_data.graphql';

type MeUser = {
  capabilities: RootMe_data$data['capabilities']
  capabilitiesInDraft?: RootMe_data$data['capabilitiesInDraft']
  draftContext?: Partial<DraftContext>;
};

describe('useGranted', () => {
  const draftContext = {
    id: 'draft-test',
    name: 'Draft Test',
    draft_status: 'open',
  };
  
  beforeEach(() => {
    vi.resetAllMocks();
  });

  const mockAuthMe = (me: MeUser) => {
    (useAuth as Mock).mockReturnValue({ me });
  };

  it('should throws if SETTINGS capability is used', () => {
    mockAuthMe({ capabilities: [] });
    expect(() => useGranted([SETTINGS])).toThrow();
  });

  it('should returns true if user has BYPASS', () => {
    mockAuthMe({
      capabilities: [{ name: BYPASS }],
    });

    expect(useGranted(['ANYTHING'])).toBe(true);
  });

  it('should returns true if any capability matches parent capability (OR mode)', () => {
    mockAuthMe({
      capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }],
    });

    expect(useGranted(['KNOWLEDGE'])).toBe(true);
  });

  it('returns false if no capability matches (OR mode)', () => {
    mockAuthMe({
      capabilities: [{ name: 'KNOWLEDGE' }],
    });

    expect(useGranted(['KNOWLEDGE_KNUPDATE'])).toBe(false);
  });

  it('returns true only if all capabilities match when matchAll = true', () => {
    mockAuthMe({
      capabilities: [{ name: 'KNOWLEDGE' }, { name: 'KNOWLEDGE_KNUPDATE' }],
    });

    expect(useGranted(['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE'], true)).toBe(true);
    expect(useGranted(['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE_KNDELETE'], true)).toBe(false);
  });

  it('uses draft capabilities when user is in draft mode', () => {
    mockAuthMe({
      draftContext: draftContext,
      capabilities: [{ name: 'KNOWLEDGE' }],
      capabilitiesInDraft: [{ name: 'KNOWLEDGE_KNUPDATE' }]
    });

    expect(useGranted(['KNOWLEDGE_KNUPDATE'])).toBe(true);
  });

  it('merges capabilities uniquely without duplicates', () => {
    mockAuthMe({
      draftContext: draftContext,
      capabilities: [{ name: 'KNOWLEDGE' }],
      capabilitiesInDraft: [{ name: 'KNOWLEDGE' }, { name: 'KNOWLEDGE_KNUPDATE' }]
    });

    expect(useGranted(['KNOWLEDGE_KNUPDATE'])).toBe(true);
  });

  it('returns false if capability list is empty', () => {
    mockAuthMe({
      capabilities: [{ name: 'KNOWLEDGE' }],
    });

    expect(useGranted([])).toBe(false);
  });

});
