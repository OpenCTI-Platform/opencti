import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext } from '../../../../src/types/user';
import conf from '../../../../src/config/conf';

const forwards = new Map<string, string>();
// Leases per draft: writer id -> end of the lease
const writers = new Map<string, Map<string, number>>();

vi.mock('../../../../src/database/redis', () => ({
  redisAddDraftWriter: vi.fn(async (draftId: string, writerId: string, leaseMs: number) => {
    const leases = writers.get(draftId) ?? new Map<string, number>();
    leases.set(writerId, Date.now() + leaseMs);
    writers.set(draftId, leases);
  }),
  redisRemoveDraftWriter: vi.fn(async (draftId: string, writerId: string) => {
    writers.get(draftId)?.delete(writerId);
  }),
  redisListDraftWriters: vi.fn(async (draftId: string, lapsedKeptMs: number) => [...(writers.get(draftId)?.entries() ?? [])]
    .filter(([, end]) => end > Date.now() - lapsedKeptMs)
    .map(([writerId]) => writerId)),
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
  enterDraft,
  forwardDraftWork,
  openDraftForwarding,
  registerDraftClosureHandler,
  resolveDraftForward,
  runDraftClosureHandlers,
} = await import('../../../../src/modules/draftWorkspace/draftWorkspace-closure');
const { redisGetDraftForward } = await import('../../../../src/database/redis');

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

describe('Requests writing into a draft of a forwarding chain', () => {
  const leases = (draftId: string) => [...(writers.get(draftId)?.entries() ?? [])]
    .filter(([, end]) => end > Date.now())
    .map(([writerId]) => writerId);

  beforeEach(() => {
    forwards.clear();
    takingOver.clear();
    writers.clear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should hold no lease in a draft outside any forwarding chain', async () => {
    const entry = await enterDraft('draft-1');
    expect(entry).toMatchObject({ draftId: 'draft-1', closed: false, writerId: null });
    expect(writers.size).toBe(0);
  });

  it('should hold a lease on an open draft of a chain until the request ends', async () => {
    await openDraftForwarding('draft-1');
    const entry = await enterDraft('draft-1');
    expect(entry).toMatchObject({ draftId: 'draft-1', closed: false });
    expect(leases('draft-1')).toEqual([entry.writerId]);
    await entry.release();
    expect(leases('draft-1')).toEqual([]);
  });

  it('should hold the lease on the draft that took over only', async () => {
    await forwardDraftWork('draft-1', 'draft-2');
    await forwardDraftWork('draft-2', 'draft-3');
    const entry = await enterDraft('draft-1');
    expect(entry).toMatchObject({ draftId: 'draft-3', closed: false });
    expect(leases('draft-1')).toEqual([]);
    expect(leases('draft-2')).toEqual([]);
    expect(leases('draft-3')).toEqual([entry.writerId]);
  });

  it('should release the leases it took when entering the draft fails', async () => {
    await forwardDraftWork('draft-1', 'draft-2');
    const lookup = vi.mocked(redisGetDraftForward);
    const lookupForward = lookup.getMockImplementation() as typeof redisGetDraftForward;
    const failure = new Error('Redis unavailable');
    const holders = (draftId: string) => writers.get(draftId)?.size ?? 0;
    // The forward lookup fails once the request holds a lease on the draft it entered first
    lookup.mockImplementationOnce(lookupForward).mockRejectedValueOnce(failure);
    await expect(enterDraft('draft-1')).rejects.toThrow('Redis unavailable');
    expect([holders('draft-1'), holders('draft-2')]).toEqual([0, 0]);
    // Then once it holds a lease on the draft taking over, after it left the first one
    lookup.mockImplementationOnce(lookupForward).mockImplementationOnce(lookupForward).mockImplementationOnce(lookupForward).mockRejectedValueOnce(failure);
    await expect(enterDraft('draft-1')).rejects.toThrow('Redis unavailable');
    expect([holders('draft-1'), holders('draft-2')]).toEqual([0, 0]);
    // The next request enters as usual
    const entry = await enterDraft('draft-1');
    expect(entry).toMatchObject({ draftId: 'draft-2', closed: false });
    expect(leases('draft-2')).toEqual([entry.writerId]);
  });

  it('should refuse a request whose chain ended, with no lease', async () => {
    await forwardDraftWork('draft-1', 'draft-2');
    await runDraftClosureHandlers(context, 'draft-2');
    const entry = await enterDraft('draft-1');
    expect(entry).toMatchObject({ draftId: 'draft-2', closed: true, writerId: null });
    expect(leases('draft-1')).toEqual([]);
    expect(leases('draft-2')).toEqual([]);
  });

  it('should read or remove the content of a closing draft only once the requests writing into it ended', async () => {
    await openDraftForwarding('draft-1');
    takingOver.set('draft-1', 'draft-2');
    const writing = await enterDraft('draft-1');
    let closureDone = false;
    const closure = runDraftClosureHandlers(context, 'draft-1').then(() => {
      closureDone = true;
    });
    await new Promise((resolve) => {
      setTimeout(resolve, 500);
    });
    expect(closureDone).toBe(false);
    // A request entering now goes to the draft taking over: the closure does not wait for it
    const late = await enterDraft('draft-1');
    expect(late.draftId).toBe('draft-2');
    await writing.release();
    await closure;
    expect(closureDone).toBe(true);
    expect(leases('draft-2')).toEqual([late.writerId]);
  });

  it('should never make the request closing a draft wait for itself', async () => {
    await openDraftForwarding('draft-1');
    const own = await enterDraft('draft-1');
    await runDraftClosureHandlers({ draft_writer_id: own.writerId } as AuthContext, 'draft-1');
    expect(await resolveDraftForward('draft-1')).toEqual(closed('draft-1'));
  });

  it('should refuse to close a draft still written into once the drain delay is over', async () => {
    vi.useFakeTimers();
    await openDraftForwarding('draft-1');
    await enterDraft('draft-1');
    const outcome = expect(runDraftClosureHandlers(context, 'draft-1')).rejects
      .toThrow('The draft still receives work that started before it was closed, retry in a moment');
    await vi.advanceTimersByTimeAsync(31 * 1000);
    await outcome;
  });

  it('should hold a closure back for a lease that ended unreleased while its request may still write, and no longer', async () => {
    vi.useFakeTimers();
    await openDraftForwarding('draft-1');
    // Neither renewed nor released: a node stopped mid-request, or a request whose renewals Redis refused
    writers.set('draft-1', new Map([['lapsed-writer', Date.now() + 2 * 60 * 1000]]));
    await vi.advanceTimersByTimeAsync(2 * 60 * 1000 + 1);
    const refused = expect(runDraftClosureHandlers(context, 'draft-1')).rejects
      .toThrow('The draft still receives work that started before it was closed, retry in a moment');
    await vi.advanceTimersByTimeAsync(31 * 1000);
    await refused;
    // Past the longest search engine request, the request cannot write any more
    await vi.advanceTimersByTimeAsync(conf.get('elasticsearch:request_timeout') || 3600000);
    await runDraftClosureHandlers(context, 'draft-1');
    expect(await resolveDraftForward('draft-1')).toEqual(closed('draft-1'));
  });

  it('should renew the lease of a running request past its expiry, until the request is released', async () => {
    vi.useFakeTimers();
    await openDraftForwarding('draft-1');
    const entry = await enterDraft('draft-1');
    await vi.advanceTimersByTimeAsync(10 * 60 * 1000);
    expect(leases('draft-1')).toEqual([entry.writerId]);
    await entry.release();
    await vi.advanceTimersByTimeAsync(60 * 1000);
    expect(leases('draft-1')).toEqual([]);
    // Releasing twice is harmless
    await entry.release();
    expect(leases('draft-1')).toEqual([]);
  });

  it('should keep renewing the lease of a request running past the HTTP timeout, until it is released', async () => {
    vi.useFakeTimers();
    await openDraftForwarding('draft-1');
    const entry = await enterDraft('draft-1');
    // The HTTP timeout closes the socket of a request, not its execution: a write can still be running
    await vi.advanceTimersByTimeAsync(45 * 60 * 1000);
    expect(leases('draft-1')).toEqual([entry.writerId]);
    await entry.release();
    expect(leases('draft-1')).toEqual([]);
  });
});
