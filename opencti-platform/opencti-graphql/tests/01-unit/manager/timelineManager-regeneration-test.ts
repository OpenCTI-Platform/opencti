import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext } from '../../../src/types/user';

const queue = vi.hoisted(() => ({
  claimDueTimelineRegenerations: vi.fn(),
  acknowledgeTimelineRegeneration: vi.fn(),
  retryTimelineRegeneration: vi.fn(),
  clearTimelineRegenerationAttempts: vi.fn(),
}));
const engine = vi.hoisted(() => ({ regenerateContainerTimeline: vi.fn() }));

vi.mock('../../../src/modules/timeline/timeline-queue', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/timeline/timeline-queue')>()),
  ...queue,
}));
vi.mock('../../../src/modules/timeline/timeline-engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/timeline/timeline-engine')>()),
  ...engine,
}));

import { processDueTimelineRegenerations } from '../../../src/manager/timelineManager';

const context = {} as AuthContext;

describe('Timeline manager regenerations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    queue.claimDueTimelineRegenerations.mockResolvedValue({ containerIds: ['case-1'], lease: 42 });
    queue.acknowledgeTimelineRegeneration.mockResolvedValue(true);
    queue.clearTimelineRegenerationAttempts.mockResolvedValue(undefined);
  });

  it('should release the claim of a regenerated container', async () => {
    engine.regenerateContainerTimeline.mockResolvedValue(null);
    await processDueTimelineRegenerations(context);
    expect(queue.clearTimelineRegenerationAttempts).toHaveBeenCalledWith('case-1');
    // Released with the lease of its claim: a later claim of the container would keep its own
    expect(queue.acknowledgeTimelineRegeneration).toHaveBeenCalledWith('case-1', 42);
  });

  it('should release the claim of a failed regeneration once its retry is scheduled, or once its retries are exhausted', async () => {
    engine.regenerateContainerTimeline.mockRejectedValue(new Error('regeneration failed'));
    queue.retryTimelineRegeneration.mockResolvedValueOnce(true).mockResolvedValueOnce(false);
    await processDueTimelineRegenerations(context);
    await processDueTimelineRegenerations(context);
    expect(queue.retryTimelineRegeneration).toHaveBeenCalledTimes(2);
    expect(queue.acknowledgeTimelineRegeneration).toHaveBeenCalledTimes(2);
  });

  it('should keep the claim of a failed regeneration whose retry cannot be scheduled, for its lease to hand it out again', async () => {
    engine.regenerateContainerTimeline.mockRejectedValue(new Error('regeneration failed'));
    queue.retryTimelineRegeneration.mockRejectedValue(new Error('queue unavailable'));
    await processDueTimelineRegenerations(context);
    expect(queue.retryTimelineRegeneration).toHaveBeenCalledWith('case-1');
    expect(queue.acknowledgeTimelineRegeneration).not.toHaveBeenCalled();
  });
});
