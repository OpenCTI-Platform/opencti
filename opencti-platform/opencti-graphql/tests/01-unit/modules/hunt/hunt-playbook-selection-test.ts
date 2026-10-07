import { beforeEach, describe, expect, it, vi } from 'vitest';
// The registry imports the hunt component, which imports it back through the playbook utilities: it is loaded first
import '../../../../src/modules/playbook/playbook-components';
import { topEntitiesList } from '../../../../src/database/middleware-loader';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import { type HuntComponentConfiguration, resolvePlaybookHunts } from '../../../../src/modules/playbook/components/hunt-component';
import type { StixObject } from '../../../../src/types/stix-2-1-common';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  topEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

const configuration = {
  applyToElements: 'only-main',
  hunt_ids: [],
  security_platform_ids: [],
  time_window_hours: 0,
  max_hunts: 2,
  wait_for_results: true,
  include_results: true,
} as HuntComponentConfiguration;

const refs = Array.from({ length: 1200 }, (_, index) => `attack-pattern--ref-${index}`);
const report = { id: 'report--1', type: 'report', object_refs: refs } as unknown as StixObject;

type SearchArgs = { filters: { filterGroups: { filters: { values: string[] }[] }[] } };

// The values of the hunt filters the search was given
const searchedIds = (call: unknown[]) => (call[3] as SearchArgs).filters.filterGroups[0].filters[0].values;

describe('Hunts selected by a playbook step from its elements', () => {
  beforeEach(() => {
    vi.mocked(topEntitiesList).mockReset();
    vi.mocked(findByIds).mockImplementation((async (_context: AuthContext, _user: unknown, ids: string[]) => ids.map((id) => ({ internal_id: `internal-${id}` }))) as never);
  });

  it('should find a hunt covering a technique past the 500th ref of a container', async () => {
    const hunt = { internal_id: 'hunt-1', last_run_at: '2026-10-01T00:00:00.000Z' };
    vi.mocked(topEntitiesList).mockImplementation((async (_context: AuthContext, _user: unknown, _types: string[], args: SearchArgs) => {
      return args.filters.filterGroups[0].filters[0].values.includes('internal-attack-pattern--ref-1100') ? [hunt] : [];
    }) as never);
    const hunts = await resolvePlaybookHunts({} as AuthContext, [report], configuration);
    expect(vi.mocked(findByIds).mock.calls[0][2]).toHaveLength(1201);
    expect(vi.mocked(topEntitiesList).mock.calls.map((call) => searchedIds(call).length)).toEqual([500, 500, 201]);
    expect(hunts).toEqual([hunt]);
  });

  it('should keep the least recently run hunts across the slices, a hunt never run last', async () => {
    const neverRun = { internal_id: 'hunt-never' } as BasicStoreEntityHunt;
    const recent = { internal_id: 'hunt-recent', last_run_at: '2026-10-03T00:00:00.000Z' } as BasicStoreEntityHunt;
    const oldest = { internal_id: 'hunt-oldest', last_run_at: '2026-10-01T00:00:00.000Z' } as BasicStoreEntityHunt;
    vi.mocked(topEntitiesList)
      .mockResolvedValueOnce([recent, neverRun] as never)
      .mockResolvedValueOnce([oldest, recent] as never)
      .mockResolvedValueOnce([] as never);
    const hunts = await resolvePlaybookHunts({} as AuthContext, [report], configuration);
    expect(hunts.map((hunt) => hunt.internal_id)).toEqual(['hunt-oldest', 'hunt-recent']);
  });

  it('should search once for the refs of a small container', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([] as never);
    const small = { id: 'report--2', type: 'report', object_refs: refs.slice(0, 3) } as unknown as StixObject;
    await resolvePlaybookHunts({} as AuthContext, [small], configuration);
    expect(topEntitiesList).toHaveBeenCalledTimes(1);
    expect(searchedIds(vi.mocked(topEntitiesList).mock.calls[0])).toHaveLength(4);
  });
});
