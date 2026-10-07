import { describe, expect, it, vi } from 'vitest';
import { addObservedData } from '../../../../src/domain/observedData';
import { addStixCyberObservable } from '../../../../src/domain/stixCyberObservable';
import { createHuntHitObservations } from '../../../../src/modules/hunt/hunt-hit-observations';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/domain/stixCyberObservable', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/domain/stixCyberObservable')>(),
  addStixCyberObservable: vi.fn(async () => ({ internal_id: 'hostname-1' })),
}));

vi.mock('../../../../src/domain/observedData', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/domain/observedData')>(),
  addObservedData: vi.fn(async () => ({ internal_id: 'observed-data-1' })),
}));

describe('Hunt hit observations', () => {
  it('should attribute the observed data of a sampled hit to its run', async () => {
    const run = {
      internal_id: 'run-1',
      time_window_start: '2026-10-04T00:00:00.000Z',
      time_window_end: '2026-10-05T00:00:00.000Z',
      hits_sample: [{ event_id: null, timestamp: '2026-10-04T08:00:00.000Z', detection: null, matched: [], host: 'ws-042', user: null, process: null }],
    } as unknown as BasicStoreEntityHuntRun;
    const result = await createHuntHitObservations({} as AuthContext, {} as BasicStoreEntityHunt, run);
    expect(result).toEqual({ observedDataIds: ['observed-data-1'], observableIds: ['hostname-1'] });
    expect(addStixCyberObservable).toHaveBeenCalledTimes(1);
    expect(addObservedData).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({
      objects: ['hostname-1'],
      x_opencti_hunt_run_id: 'run-1',
      first_observed: '2026-10-04T08:00:00.000Z',
      last_observed: '2026-10-04T08:00:00.000Z',
    }));
  });

  it('should give each hit of each run its own observed data, even when hits name the same observables', async () => {
    vi.mocked(addObservedData).mockClear();
    const hit = (eventId: string, timestamp: string) => ({ event_id: eventId, timestamp, detection: null, matched: [], host: 'ws-042', user: null, process: null });
    const runOf = (id: string) => ({
      internal_id: id,
      time_window_start: '2026-10-04T00:00:00.000Z',
      time_window_end: '2026-10-05T00:00:00.000Z',
      hits_sample: [hit('event-1', '2026-10-04T08:00:00.000Z'), hit('event-2', '2026-10-04T09:00:00.000Z')],
    } as unknown as BasicStoreEntityHuntRun);
    await createHuntHitObservations({} as AuthContext, {} as BasicStoreEntityHunt, runOf('run-1'));
    await createHuntHitObservations({} as AuthContext, {} as BasicStoreEntityHunt, runOf('run-2'));
    await createHuntHitObservations({} as AuthContext, {} as BasicStoreEntityHunt, runOf('run-1'));
    const inputs = vi.mocked(addObservedData).mock.calls.map(([, , input]) => input);
    expect(inputs.map((input) => input.objects)).toEqual(Array(6).fill(['hostname-1']));
    const ids = inputs.map((input) => input.standard_id);
    expect(ids.every((id) => /^observed-data--[\da-f-]{36}$/.test(id))).toBe(true);
    expect(new Set(ids.slice(0, 4)).size).toBe(4);
    // A finalization replayed upserts the same observed data
    expect(ids.slice(4)).toEqual(ids.slice(0, 2));
    expect(inputs[1]).toMatchObject({ x_opencti_hunt_run_id: 'run-1', first_observed: '2026-10-04T09:00:00.000Z' });
    expect(inputs[2]).toMatchObject({ x_opencti_hunt_run_id: 'run-2', first_observed: '2026-10-04T08:00:00.000Z' });
  });
});
