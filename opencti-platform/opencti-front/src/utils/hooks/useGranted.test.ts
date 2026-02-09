import { DraftContext } from './useDraftContext';
import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import useAuth from './useAuth';
import useGranted, { SETTINGS, BYPASS, KNOWLEDGE, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNASKIMPORT } from './useGranted';
import { RootMe_data$data } from '../../private/__generated__/RootMe_data.graphql';

vi.mock('./useAuth', () => ({ default: vi.fn() }));
vi.mock('./useHelper', () => ({ default: vi.fn() }));

type MeUser = {
  id?: string;
  capabilities: RootMe_data$data['capabilities'];
  capabilitiesInDraft?: RootMe_data$data['capabilitiesInDraft'];
  draftContext?: Partial<DraftContext> | null;
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
    (useAuth as Mock).mockReturnValue({ me: { id: 'user-id', ...me } });
  };

  // --- Core Security & Bypass ---

  it('should throw if SETTINGS capability is used', () => {
    mockAuthMe({ capabilities: [] });
    expect(() => useGranted([SETTINGS])).toThrow();
  });

  it('should return true if user has BYPASS', () => {
    mockAuthMe({ capabilities: [{ name: BYPASS }] });
    expect(useGranted(['ANYTHING'])).toBe(true);
  });

  it('should return false if user has a capability that only contains BYPASS as a substring', () => {
    mockAuthMe({
      capabilities: [
        { name: 'KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE' },
        { name: 'KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS' },
      ],
    });

    expect(useGranted([BYPASS])).toBe(false);
  });

  // --- Base Capability Logic (OR / AND) ---

  it('should return true if any capability matches (OR mode / default)', () => {
    mockAuthMe({ capabilities: [{ name: KNOWLEDGE_KNUPDATE }] });
    expect(useGranted([KNOWLEDGE])).toBe(true); // Parent matches because child includes parent string
  });

  it('should return false if no capability matches', () => {
    mockAuthMe({ capabilities: [{ name: KNOWLEDGE }] });
    expect(useGranted([KNOWLEDGE_KNUPDATE])).toBe(false); // Child req doesn't match parent user
  });

  it('should handle matchAll (AND mode) correctly', () => {
    mockAuthMe({
      capabilities: [{ name: KNOWLEDGE }, { name: KNOWLEDGE_KNASKIMPORT }],
    });

    expect(useGranted([KNOWLEDGE, KNOWLEDGE_KNASKIMPORT], true)).toBe(true);
    expect(useGranted([KNOWLEDGE, 'UNKNOWN'], true)).toBe(false);
  });

  // --- Draft Context Logic ---

  it('should use draft capabilities when user is in draft context', () => {
    mockAuthMe({
      draftContext,
      capabilities: [{ name: KNOWLEDGE }],
      capabilitiesInDraft: [{ name: KNOWLEDGE_KNASKIMPORT }],
    });

    // Should be true because KNOWLEDGE_KNASKIMPORT is in the draft pool and context is active
    expect(useGranted([KNOWLEDGE_KNASKIMPORT])).toBe(true);
  });

  it('should satisfy matchAll by merging base and draft pools in draft context', () => {
    mockAuthMe({
      draftContext,
      capabilities: [{ name: KNOWLEDGE }],
      capabilitiesInDraft: [{ name: KNOWLEDGE_KNASKIMPORT }],
    });

    // User has KNOWLEDGE (base) AND KNOWLEDGE_KNASKIMPORT (draft)
    expect(useGranted([KNOWLEDGE, KNOWLEDGE_KNASKIMPORT], true)).toBe(true);
  });

  it('should not use draft capabilities if user is NOT in draft context', () => {
    mockAuthMe({
      draftContext: null,
      capabilities: [{ name: KNOWLEDGE }],
      capabilitiesInDraft: [{ name: KNOWLEDGE_KNASKIMPORT }],
    });

    expect(useGranted([KNOWLEDGE_KNASKIMPORT])).toBe(false);
  });

  // --- Explicit Options Logic ---

  it('should check options.capabilitiesInDraft against userCapabilitiesInDraft regardless of context', () => {
    mockAuthMe({
      draftContext: null, // No context
      capabilities: [{ name: KNOWLEDGE }],
      capabilitiesInDraft: [{ name: KNOWLEDGE_KNASKIMPORT }],
    });

    // Explicitly asking to check the draft pool for KNOWLEDGE_KNASKIMPORT
    expect(useGranted([], false, { capabilitiesInDraft: [KNOWLEDGE_KNASKIMPORT] })).toBe(true);
  });

  // --- Edge Cases ---

  it('should return false if the requested capability list is empty', () => {
    mockAuthMe({ capabilities: [{ name: KNOWLEDGE }] });
    expect(useGranted([])).toBe(false);
  });

  it('should handle undefined or null capabilities gracefully', () => {
    // @ts-expect-error Testing invalid input
    mockAuthMe({ capabilities: null, capabilitiesInDraft: undefined });
    expect(useGranted([KNOWLEDGE])).toBe(false);
  });
});
