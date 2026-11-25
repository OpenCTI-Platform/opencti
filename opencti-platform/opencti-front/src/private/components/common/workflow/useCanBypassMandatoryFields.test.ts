import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useCanBypassMandatoryFields from './useCanBypassMandatoryFields';

type Me = {
  capabilities: { name: string }[];
  capabilitiesInDraft: { name: string }[];
  draftContext: { id: string } | null;
};

const mocks = vi.hoisted(() => ({ me: undefined as unknown as Me }));

vi.mock('../../../../utils/hooks/useAuth', () => ({ default: () => ({ me: mocks.me }) }));

const BYPASS_FIELDS = 'KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS';

describe('useCanBypassMandatoryFields', () => {
  beforeEach(() => {
    mocks.me = { capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }], capabilitiesInDraft: [], draftContext: null };
  });

  it('is false for a user without the capability', () => {
    expect(renderHook(() => useCanBypassMandatoryFields()).result.current).toBe(false);
  });

  it('is true for a user holding the capability', () => {
    mocks.me.capabilities = [{ name: BYPASS_FIELDS }];
    expect(renderHook(() => useCanBypassMandatoryFields()).result.current).toBe(true);
  });

  it('is true for a BYPASS user', () => {
    mocks.me.capabilities = [{ name: 'BYPASS' }];
    expect(renderHook(() => useCanBypassMandatoryFields()).result.current).toBe(true);
  });

  it('ignores a capability granted only in a draft, even inside a draft', () => {
    // the backend checks required inputs without the draft context, so it would still reject the transition
    mocks.me.capabilitiesInDraft = [{ name: BYPASS_FIELDS }];
    mocks.me.draftContext = { id: 'draft-1' };
    expect(renderHook(() => useCanBypassMandatoryFields()).result.current).toBe(false);
  });
});
