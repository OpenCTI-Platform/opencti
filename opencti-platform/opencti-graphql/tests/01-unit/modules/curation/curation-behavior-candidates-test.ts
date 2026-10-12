import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { findBehaviorCandidateIds } from '../../../../src/modules/curation/curation-scan';
import { fullRelationsList } from '../../../../src/database/middleware-loader';
import { elAggregationRelationsCount } from '../../../../src/database/engine';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../../src/schema/stixDomainObject';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullRelationsList: vi.fn(),
}));
vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elAggregationRelationsCount: vi.fn(),
}));

const context = {} as AuthContext;
const usesTechniques = (...techniqueIds: string[]) => vi.mocked(fullRelationsList).mockImplementation(async (_context, _user, _type, opts: any) => {
  await opts.callback(techniqueIds.map((toId) => ({ toId })));
  return [] as never;
});

describe('behavior candidates of an entity', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('are the entities sharing the most techniques with it, over the whole graph, the entity itself excluded', async () => {
    usesTechniques('t1059', 't1566', 't1059');
    vi.mocked(elAggregationRelationsCount).mockResolvedValue([
      { label: 'set-self', value: 2 },
      { label: 'set-few', value: 1 },
      { label: 'set-many', value: 2 },
    ]);
    await expect(findBehaviorCandidateIds(context, 'set-self', [ENTITY_TYPE_INTRUSION_SET])).resolves.toEqual(['set-many', 'set-few']);
    const options = vi.mocked(elAggregationRelationsCount).mock.calls[0][3] as any;
    const [techniques, users] = options.searchOptions.filters.filters;
    expect(techniques.nested[0]).toEqual({ key: 'internal_id', values: ['t1059', 't1566'] });
    expect(users.nested[0]).toEqual({ key: 'types', values: [ENTITY_TYPE_INTRUSION_SET] });
    // Only the users of the techniques are counted, not the techniques themselves.
    expect(options.aggregationOptions.filters.filters).toEqual([users]);
  });

  it('are none, without any aggregation, for an entity that uses no technique', async () => {
    usesTechniques();
    await expect(findBehaviorCandidateIds(context, 'set-self', [ENTITY_TYPE_INTRUSION_SET])).resolves.toEqual([]);
    expect(elAggregationRelationsCount).not.toHaveBeenCalled();
  });
});
