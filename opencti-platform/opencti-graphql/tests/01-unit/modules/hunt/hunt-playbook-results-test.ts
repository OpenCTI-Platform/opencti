import { beforeEach, describe, expect, it, vi } from 'vitest';
import { stixLoadByIds } from '../../../../src/database/middleware';
import { listHuntConnectors } from '../../../../src/modules/hunt/hunt-dispatch';
import { HUNT_PLAYBOOK_MAX_RESULTS, loadHuntRunResultsForPlaybook } from '../../../../src/modules/hunt/hunt-playbook';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { resolveUserByIdFromCache } from '../../../../src/modules/user/user-domain';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  stixLoadByIds: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-dispatch', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-dispatch')>(),
  listHuntConnectors: vi.fn(),
}));

vi.mock('../../../../src/modules/user/user-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/user/user-domain')>(),
  resolveUserByIdFromCache: vi.fn(),
}));

const context = {} as AuthContext;
const stix = (id: string) => ({ id: `indicator--${id}`, type: 'indicator', extensions: { [STIX_EXT_OCTI]: { id } } });
const run = (id: string, connectorId: string, resultIds: string[]) => ({ internal_id: id, connector_id: connectorId, result_ids: resultIds } as unknown as BasicStoreEntityHuntRun);
// What each connector identity can read
const readable: Record<string, string[]> = {};

describe('Hunt run results given to a playbook', () => {
  beforeEach(() => {
    vi.mocked(listHuntConnectors).mockResolvedValue([
      { internal_id: 'connector-a', connector_user_id: 'user-a' },
      { internal_id: 'connector-b', connector_user_id: 'user-b' },
    ] as never);
    vi.mocked(resolveUserByIdFromCache).mockImplementation(async (_context, userId) => ({ id: userId } as AuthUser));
    vi.mocked(stixLoadByIds).mockReset();
    vi.mocked(stixLoadByIds).mockImplementation(async (_context, user, ids) => ids.filter((id) => (readable[user.id] ?? []).includes(id)).map(stix) as never);
  });

  it('should let a connector that reads an object add it when the connector of an earlier run cannot', async () => {
    readable['user-a'] = ['object-1'];
    readable['user-b'] = ['object-2', 'object-3'];
    const results = await loadHuntRunResultsForPlaybook(context, [run('run-1', 'connector-a', ['object-1', 'object-2']), run('run-2', 'connector-b', ['object-2', 'object-3'])], new Set());
    expect(results.map((result) => result.extensions[STIX_EXT_OCTI].id)).toEqual(['object-1', 'object-2', 'object-3']);
  });

  it('should fill the cap with readable objects, the ids a connector cannot read taking no place', async () => {
    const missing = Array.from({ length: HUNT_PLAYBOOK_MAX_RESULTS }, (_, index) => `missing-${index}`);
    readable['user-a'] = ['object-1', 'object-2'];
    const results = await loadHuntRunResultsForPlaybook(context, [run('run-1', 'connector-a', [...missing, 'object-1', 'object-2'])], new Set());
    expect(results.map((result) => result.extensions[STIX_EXT_OCTI].id)).toEqual(['object-1', 'object-2']);
  });

  it('should add no object already in the bundle, known by its internal or its STIX id', async () => {
    readable['user-a'] = ['object-1', 'object-2', 'object-3'];
    const results = await loadHuntRunResultsForPlaybook(context, [run('run-1', 'connector-a', ['object-1', 'object-2', 'object-3'])], new Set(['object-1', 'indicator--object-2']));
    expect(results.map((result) => result.extensions[STIX_EXT_OCTI].id)).toEqual(['object-3']);
    expect(vi.mocked(stixLoadByIds).mock.calls[0][2]).toEqual(['object-2', 'object-3']);
  });

  it('should stop at the cap', async () => {
    const ids = Array.from({ length: HUNT_PLAYBOOK_MAX_RESULTS + 10 }, (_, index) => `object-${index}`);
    readable['user-a'] = ids;
    const results = await loadHuntRunResultsForPlaybook(context, [run('run-1', 'connector-a', ids)], new Set());
    expect(results).toHaveLength(HUNT_PLAYBOOK_MAX_RESULTS);
    expect(stixLoadByIds).toHaveBeenCalledTimes(1);
  });
});
