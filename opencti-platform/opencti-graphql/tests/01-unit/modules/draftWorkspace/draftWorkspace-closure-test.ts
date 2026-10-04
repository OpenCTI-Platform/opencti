import { beforeEach, describe, expect, it, vi } from 'vitest';

const forwards = new Map<string, string>();

vi.mock('../../../../src/database/redis', () => ({
  redisSetDraftForward: vi.fn(async (closedDraftId: string, nextDraftId: string) => {
    forwards.set(closedDraftId, nextDraftId);
  }),
  redisGetDraftForward: vi.fn(async (draftId: string) => forwards.get(draftId) ?? null),
}));

const { forwardDraftWork, resolveDraftForward } = await import('../../../../src/modules/draftWorkspace/draftWorkspace-closure');

describe('Draft work forwarding', () => {
  beforeEach(() => {
    forwards.clear();
  });

  it('should keep the work of a draft that never closed in that draft', async () => {
    expect(await resolveDraftForward('draft-1')).toBe('draft-1');
  });

  it('should send the work of a closed draft to the draft that took over', async () => {
    await forwardDraftWork('draft-1', 'draft-2');
    expect(await resolveDraftForward('draft-1')).toBe('draft-2');
    expect(await resolveDraftForward('draft-2')).toBe('draft-2');
  });

  it('should follow the drafts that successively took over', async () => {
    await forwardDraftWork('draft-1', 'draft-2');
    await forwardDraftWork('draft-2', 'draft-3');
    expect(await resolveDraftForward('draft-1')).toBe('draft-3');
  });

  it('should reach the current draft after any number of renewals, then in one step', async () => {
    for (let i = 0; i < 25; i += 1) {
      await forwardDraftWork(`draft-${i}`, `draft-${i + 1}`);
    }
    expect(await resolveDraftForward('draft-0')).toBe('draft-25');
    expect(forwards.get('draft-0')).toBe('draft-25');
    await forwardDraftWork('draft-25', 'draft-26');
    expect(await resolveDraftForward('draft-0')).toBe('draft-26');
    expect(await resolveDraftForward('draft-24')).toBe('draft-26');
  });

  it('should stop a longer loop at the last draft before it', async () => {
    await forwardDraftWork('draft-1', 'draft-2');
    await forwardDraftWork('draft-2', 'draft-3');
    await forwardDraftWork('draft-3', 'draft-1');
    expect(await resolveDraftForward('draft-1')).toBe('draft-3');
  });

  it('should never forward a draft to itself nor loop', async () => {
    await forwardDraftWork('draft-1', 'draft-1');
    expect(forwards.size).toBe(0);
    await forwardDraftWork('draft-1', 'draft-2');
    await forwardDraftWork('draft-2', 'draft-1');
    expect(await resolveDraftForward('draft-1')).toBe('draft-2');
  });
});
