import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesListFromCache } from '../../../../src/database/cache';
import { isEnterpriseEdition } from '../../../../src/enterprise-edition/ee';
import { stixLoadByFilters } from '../../../../src/database/middleware';
import { playbookExecutor } from '../../../../src/manager/playbookManager/playbookExecutor';
import { buildPlaybookStreamHandler, handlePlaybookCrons } from '../../../../src/manager/playbookManager/playbookManager';
import { createEventWatermark, createTriggerScheduler, playbookTriggerScheduler } from '../../../../src/manager/playbookManager/playbookTriggerScheduler';
import type { BasicStoreEntityPlaybook } from '../../../../src/modules/playbook/playbook-types';
import type { SseEvent, StreamDataEvent } from '../../../../src/types/event';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntitiesListFromCache: vi.fn(),
}));

vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>(),
  isEnterpriseEdition: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  stixLoadByFilters: vi.fn(),
}));

vi.mock('../../../../src/utils/filtering/filtering-stix/stix-filtering', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/utils/filtering/filtering-stix/stix-filtering')>(),
  isStixMatchFilterGroup: vi.fn(async () => true),
}));

vi.mock('../../../../src/utils/filtering/filtering-resolution', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/utils/filtering/filtering-resolution')>(),
  convertFiltersToQueryOptions: vi.fn(async () => ({})),
}));

vi.mock('../../../../src/utils/filtering/filtering-utils', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/utils/filtering/filtering-utils')>(),
  convertRelationRefsFilterKeys: vi.fn((filters) => filters),
}));

vi.mock('../../../../src/manager/playbookManager/playbookExecutor', () => ({
  playbookExecutor: vi.fn(async () => {}),
}));

type Deferred = { promise: Promise<void>; resolve: () => void };
const deferred = (): Deferred => {
  let resolve: () => void = () => {};
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
};

const flushMicrotasks = async () => {
  for (let i = 0; i < 20; i += 1) {
    await Promise.resolve();
  }
};

const streamDefinition = JSON.stringify({
  nodes: [{
    id: 'start-node',
    name: 'Stream start',
    component_id: 'PLAYBOOK_INTERNAL_DATA_STREAM',
    configuration: JSON.stringify({ create: true, update: true, delete: false, filters: '' }),
  }],
  links: [],
});

const cronDefinition = JSON.stringify({
  nodes: [{
    id: 'start-node',
    name: 'Cron start',
    component_id: 'PLAYBOOK_INTERNAL_DATA_CRON',
    configuration: JSON.stringify({ period: 'minute', triggerTime: '', onlyLast: false, includeAll: true, filters: '{}' }),
  }],
  links: [],
});

const buildPlaybook = (id: string, definition: string) => ({
  id,
  internal_id: id,
  name: `playbook ${id}`,
  playbook_start: 'start-node',
  playbook_definition: definition,
} as unknown as BasicStoreEntityPlaybook);

const streamEvent = (id: string): SseEvent<StreamDataEvent> => ({
  id,
  event: 'create',
  data: {
    type: 'create',
    scope: 'external',
    origin: {},
    data: { id: `indicator--${id}`, type: 'indicator' },
  },
} as unknown as SseEvent<StreamDataEvent>);

describe('Playbook trigger scheduler', () => {
  it('runs the executions of one playbook in order and other playbooks in parallel', async () => {
    const scheduler = createTriggerScheduler('test', { maxConcurrency: 4 });
    const slow = deferred();
    const order: string[] = [];
    const a1 = scheduler.run('A', async () => {
      order.push('A1 start');
      await slow.promise;
      order.push('A1 end');
    });
    const a2 = scheduler.run('A', async () => {
      order.push('A2');
    });
    const b1 = scheduler.run('B', async () => {
      order.push('B1');
    });
    await b1;
    // B ran while A1 is still waiting; A2 waits for A1.
    expect(order).toEqual(['A1 start', 'B1']);
    slow.resolve();
    await Promise.all([a1, a2]);
    expect(order).toEqual(['A1 start', 'B1', 'A1 end', 'A2']);
    expect(scheduler.pending()).toBe(0);
  });

  it('never runs more than maxConcurrency executions at once', async () => {
    const scheduler = createTriggerScheduler('test', { maxConcurrency: 2 });
    const gates = [deferred(), deferred(), deferred()];
    let current = 0;
    let peak = 0;
    const runs = gates.map((gate, index) => scheduler.run(`P${index}`, async () => {
      current += 1;
      peak = Math.max(peak, current);
      await gate.promise;
      current -= 1;
    }));
    await flushMicrotasks();
    expect(scheduler.running()).toBe(2);
    gates.forEach((gate) => gate.resolve());
    await Promise.all(runs);
    expect(peak).toBe(2);
  });

  it('logs and absorbs an execution error, the lane goes on', async () => {
    const scheduler = createTriggerScheduler('test', { maxConcurrency: 1 });
    const done: string[] = [];
    await expect(scheduler.run('A', async () => {
      throw new Error('boom');
    })).resolves.toBeUndefined();
    await scheduler.run('A', async () => {
      done.push('next');
    });
    expect(done).toEqual(['next']);
  });

  it('applies backpressure past maxPending', async () => {
    const scheduler = createTriggerScheduler('test', { maxConcurrency: 1, maxPending: 2 });
    const gate = deferred();
    const first = scheduler.run('A', () => gate.promise);
    const second = scheduler.run('A', async () => {});
    let released = false;
    const waiting = scheduler.waitForCapacity().then(() => {
      released = true;
    });
    await flushMicrotasks();
    expect(released).toBe(false);
    gate.resolve();
    await Promise.all([first, second, waiting]);
    expect(released).toBe(true);
  });

  it('saves the stream position only up to the last event whose executions have ended', async () => {
    const saved: string[] = [];
    const watermark = createEventWatermark(async (eventId) => {
      saved.push(eventId);
    });
    const slow = deferred();
    watermark.open('1');
    watermark.track('1', slow.promise);
    watermark.close('1');
    watermark.open('2');
    watermark.track('2', Promise.resolve());
    watermark.close('2');
    await flushMicrotasks();
    await watermark.settled();
    expect(saved).toEqual([]);
    slow.resolve();
    await flushMicrotasks();
    await watermark.settled();
    expect(saved).toEqual(['2']);
    expect(watermark.tracked()).toBe(0);
  });

  it('never saves the stream position after stop', async () => {
    const saved: string[] = [];
    const watermark = createEventWatermark(async (eventId) => {
      saved.push(eventId);
    });
    const slow = deferred();
    watermark.open('1');
    watermark.track('1', slow.promise);
    watermark.close('1');
    watermark.stop();
    slow.resolve();
    await flushMicrotasks();
    await watermark.settled();
    expect(saved).toEqual([]);
  });
});

describe('Playbook manager triggers with a slow step', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(isEnterpriseEdition).mockResolvedValue(true);
  });

  it('stream: a slow execution of playbook A does not hold back playbook B on the same event', async () => {
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([
      buildPlaybook('slow-playbook', streamDefinition),
      buildPlaybook('fast-playbook', streamDefinition),
    ] as never);
    const slow = deferred();
    const ran: string[] = [];
    vi.mocked(playbookExecutor).mockImplementation(async ({ playbookId }) => {
      if (playbookId === 'slow-playbook') {
        await slow.promise;
      }
      ran.push(playbookId);
    });
    const saved: string[] = [];
    const watermark = createEventWatermark(async (eventId) => {
      saved.push(eventId);
    });
    const handler = buildPlaybookStreamHandler(watermark);

    // The handler returns without waiting for the slow AI-like step.
    await handler([streamEvent('100-0')]);
    await flushMicrotasks();
    expect(playbookExecutor).toHaveBeenCalledTimes(2);
    expect(ran).toEqual(['fast-playbook']);
    // The position is not saved while the slow execution of this event runs.
    await watermark.settled();
    expect(saved).toEqual([]);

    slow.resolve();
    await playbookTriggerScheduler.idle();
    await flushMicrotasks();
    await watermark.settled();
    expect(ran).toEqual(['fast-playbook', 'slow-playbook']);
    expect(saved).toEqual(['100-0']);
  });

  it('cron: a slow playbook does not hold back the next one, and is skipped while its previous run is going', async () => {
    vi.mocked(stixLoadByFilters).mockResolvedValue([{ id: 'indicator--00000000-0000-4000-8000-000000000001' }] as never);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([
      buildPlaybook('slow-cron', cronDefinition),
      buildPlaybook('fast-cron', cronDefinition),
    ] as never);
    const slow = deferred();
    const ran: string[] = [];
    vi.mocked(playbookExecutor).mockImplementation(async ({ playbookId }) => {
      if (playbookId === 'slow-cron') {
        await slow.promise;
      }
      ran.push(playbookId);
    });

    await handlePlaybookCrons({} as AuthContext);
    await flushMicrotasks();
    expect(ran).toEqual(['fast-cron']);

    // Next tick while slow-cron still runs: it is skipped, fast-cron runs again.
    await handlePlaybookCrons({} as AuthContext);
    await flushMicrotasks();
    expect(vi.mocked(playbookExecutor).mock.calls.map((call) => call[0].playbookId)).toEqual(['slow-cron', 'fast-cron', 'fast-cron']);

    slow.resolve();
    await playbookTriggerScheduler.idle();
    expect(ran).toEqual(['fast-cron', 'fast-cron', 'slow-cron']);
  });
});
