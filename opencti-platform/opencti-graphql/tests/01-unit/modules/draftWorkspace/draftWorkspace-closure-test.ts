import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext } from '../../../../src/types/user';

const forwards = new Map<string, string>();

vi.mock('../../../../src/database/redis', () => ({
  redisSetDraftForward: vi.fn(async (closedDraftId: string, nextDraftId: string) => {
    forwards.set(closedDraftId, nextDraftId);
  }),
  redisSetDraftForwardIfAbsent: vi.fn(async (draftId: string, value: string) => {
    if (!forwards.has(draftId)) {
      forwards.set(draftId, value);
    }
  }),
  redisGetDraftForward: vi.fn(async (draftId: string) => forwards.get(draftId) ?? null),
}));

const {
  forwardDraftWork,
  openDraftForwarding,
  registerDraftClosureHandler,
  resolveDraftForward,
  runDraftClosureHandlers,
} = await import('../../../../src/modules/draftWorkspace/draftWorkspace-closure');

const context = {} as AuthContext;
const open = (draftId: string) => ({ draftId, closed: false });
const closed = (draftId: string) => ({ draftId, closed: true });

// Stands for a module that opens a draft taking over from the one being closed (Source Intelligence quarantine)
const takingOver = new Map<string, string>();
registerDraftClosureHandler(async (_, draftId) => {
  const nextDraftId = takingOver.get(draftId);
  if (nextDraftId) {
    await forwardDraftWork(draftId, nextDraftId);
  }
});

describe('Draft work forwarding', () => {
  beforeEach(() => {
    forwards.clear();
    takingOver.clear();
  });

  it('should keep the work of a draft that never closed in that draft', async () => {
    expect(await resolveDraftForward('draft-1')).toEqual(open('draft-1'));
  });

  it('should send the work of a closed draft to the draft that took over', async () => {
    await forwardDraftWork('draft-1', 'draft-2');
    expect(await resolveDraftForward('draft-1')).toEqual(open('draft-2'));
    expect(await resolveDraftForward('draft-2')).toEqual(open('draft-2'));
  });

  it('should follow the drafts that successively took over', async () => {
    await forwardDraftWork('draft-1', 'draft-2');
    await forwardDraftWork('draft-2', 'draft-3');
    expect(await resolveDraftForward('draft-1')).toEqual(open('draft-3'));
  });

  it('should reach the current draft after any number of renewals, then in one step', async () => {
    for (let i = 0; i < 25; i += 1) {
      await forwardDraftWork(`draft-${i}`, `draft-${i + 1}`);
    }
    expect(await resolveDraftForward('draft-0')).toEqual(open('draft-25'));
    expect(forwards.get('draft-0')).toBe('draft-25');
    await forwardDraftWork('draft-25', 'draft-26');
    expect(await resolveDraftForward('draft-0')).toEqual(open('draft-26'));
    expect(await resolveDraftForward('draft-24')).toEqual(open('draft-26'));
  });

  it('should stop a longer loop at the last draft before it', async () => {
    await forwardDraftWork('draft-1', 'draft-2');
    await forwardDraftWork('draft-2', 'draft-3');
    await forwardDraftWork('draft-3', 'draft-1');
    expect(await resolveDraftForward('draft-1')).toEqual(open('draft-3'));
  });

  it('should never forward a draft to itself nor loop', async () => {
    await forwardDraftWork('draft-1', 'draft-1');
    expect(forwards.size).toBe(0);
    await forwardDraftWork('draft-1', 'draft-2');
    await forwardDraftWork('draft-2', 'draft-1');
    expect(await resolveDraftForward('draft-1')).toEqual(open('draft-2'));
  });

  it('should keep forwarding when a draft taking over replaces the closing one', async () => {
    await forwardDraftWork('draft-1', 'draft-2');
    takingOver.set('draft-2', 'draft-3');
    await runDraftClosureHandlers(context, 'draft-2');
    expect(await resolveDraftForward('draft-1')).toEqual(open('draft-3'));
    expect(await resolveDraftForward('draft-2')).toEqual(open('draft-3'));
  });

  it('should end the chain when its last draft closes with no draft taking over', async () => {
    await forwardDraftWork('draft-1', 'draft-2');
    await forwardDraftWork('draft-2', 'draft-3');
    await runDraftClosureHandlers(context, 'draft-3');
    expect(await resolveDraftForward('draft-1')).toEqual(closed('draft-3'));
    expect(await resolveDraftForward('draft-2')).toEqual(closed('draft-3'));
    expect(await resolveDraftForward('draft-3')).toEqual(closed('draft-3'));
  });

  it('should refuse the work of a draft opened for routed work once it closes with no draft taking over', async () => {
    await openDraftForwarding('draft-1');
    expect(await resolveDraftForward('draft-1')).toEqual(open('draft-1'));
    await runDraftClosureHandlers(context, 'draft-1');
    expect(await resolveDraftForward('draft-1')).toEqual(closed('draft-1'));
  });

  it('should keep forwarding a draft opened for routed work that another draft took over', async () => {
    await openDraftForwarding('draft-1');
    takingOver.set('draft-1', 'draft-2');
    await runDraftClosureHandlers(context, 'draft-1');
    expect(await resolveDraftForward('draft-1')).toEqual(open('draft-2'));
    // Opening a draft already in a chain never cuts it
    await openDraftForwarding('draft-1');
    expect(await resolveDraftForward('draft-1')).toEqual(open('draft-2'));
  });

  it('should record nothing when a draft that never received forwarded work closes', async () => {
    await runDraftClosureHandlers(context, 'draft-1');
    expect(forwards.size).toBe(0);
    expect(await resolveDraftForward('draft-1')).toEqual(open('draft-1'));
  });
});
