import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as engineModule from '../../../../src/database/engine';
import { adaptFilterToRegardingOfFilterKey } from '../../../../src/utils/filtering/filtering-completeSpecialFilterKeys';
import { FilterMode, FilterOperator } from '../../../../src/generated/graphql';
import type { Filter } from '../../../../src/generated/graphql';
import { ABSTRACT_STIX_CORE_OBJECT, buildRefRelationKey, ID_INFERRED, ID_INTERNAL } from '../../../../src/schema/general';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../../../src/schema/stixMetaObject';
import { INSTANCE_DYNAMIC_REGARDING_OF, INSTANCE_REGARDING_OF } from '../../../../src/utils/filtering/filtering-constants';
import { RELATION_IN_PIR } from '../../../../src/schema/internalRelationship';
import { ENTITY_TYPE_PIR } from '../../../../src/modules/pir/pir-types';

const CONTEXT = {} as any;
const USER = { id: 'user-1', capabilities: [] } as any;

const dynamicFilterGroup = {
  mode: FilterMode.And,
  filters: [{ key: ['source_name'], values: ['mitre-attack'], operator: FilterOperator.Eq, mode: FilterMode.Or }],
  filterGroups: [],
};

const makeDynamicRegardingOfFilter = (relationshipTypes: string[]): Filter => ({
  key: [INSTANCE_DYNAMIC_REGARDING_OF],
  operator: FilterOperator.Eq,
  mode: FilterMode.Or,
  values: [
    { key: 'relationship_type', values: relationshipTypes },
    { key: 'dynamic', values: [dynamicFilterGroup] },
  ],
} as Filter);

describe('adaptFilterToRegardingOfFilterKey — dynamic resolution', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('resolves the dynamic filters against stix core objects and external references', async () => {
    const elPaginateSpy = vi.spyOn(engineModule, 'elPaginate').mockResolvedValue([] as any);
    await adaptFilterToRegardingOfFilterKey(CONTEXT, USER, makeDynamicRegardingOfFilter(['external-reference']));

    expect(elPaginateSpy).toHaveBeenCalledTimes(1);
    const { filters } = elPaginateSpy.mock.calls[0][3] as { filters: any };
    expect(filters.filters).toEqual([
      expect.objectContaining({ key: ['entity_type'], values: [ABSTRACT_STIX_CORE_OBJECT, ENTITY_TYPE_EXTERNAL_REFERENCE], mode: 'or' }),
    ]);
    expect(filters.filterGroups).toEqual([dynamicFilterGroup]);
  });

  it('filters on the external-reference refs of the resolved external references', async () => {
    vi.spyOn(engineModule, 'elPaginate').mockResolvedValue([{ id: 'ext-ref-1' }, { id: 'ext-ref-2' }] as any);
    const { newFilterGroup } = await adaptFilterToRegardingOfFilterKey(CONTEXT, USER, makeDynamicRegardingOfFilter(['external-reference']));

    expect(newFilterGroup.filters).toEqual([
      expect.objectContaining({
        key: [buildRefRelationKey('external-reference', ID_INTERNAL), buildRefRelationKey('external-reference', ID_INFERRED)],
        values: ['ext-ref-1', 'ext-ref-2'],
        operator: FilterOperator.Eq,
      }),
    ]);
  });

  it('forces an empty result when the dynamic filters match nothing', async () => {
    vi.spyOn(engineModule, 'elPaginate').mockResolvedValue([] as any);
    const { newFilterGroup } = await adaptFilterToRegardingOfFilterKey(CONTEXT, USER, makeDynamicRegardingOfFilter(['external-reference']));

    expect(newFilterGroup.filters).toEqual([
      expect.objectContaining({ values: ['<invalid id>'] }),
    ]);
  });
});

const makeRegardingOfFilter = (values: { key: string; values: any[] }[], operator = FilterOperator.Eq): Filter => ({
  key: [INSTANCE_REGARDING_OF],
  operator,
  mode: FilterMode.Or,
  values,
} as Filter);

describe('adaptFilterToRegardingOfFilterKey — parameters check', () => {
  it('rejects a filter without id, dynamic nor relationship type', async () => {
    await expect(adaptFilterToRegardingOfFilterKey(CONTEXT, USER, makeRegardingOfFilter([])))
      .rejects.toThrow('Id or dynamic or relationship type are needed for this filtering key');
  });

  it('rejects a dynamic filter without relationship type', async () => {
    const filter = makeRegardingOfFilter([{ key: 'dynamic', values: [dynamicFilterGroup] }]);
    await expect(adaptFilterToRegardingOfFilterKey(CONTEXT, USER, filter))
      .rejects.toThrow('Relationship type is needed for dynamic in regards of filtering');
  });

  it('rejects operators other than eq and not_eq', async () => {
    const filter = makeRegardingOfFilter([{ key: 'relationship_type', values: ['targets'] }], FilterOperator.Gt);
    await expect(adaptFilterToRegardingOfFilterKey(CONTEXT, USER, filter))
      .rejects.toThrow('regardingOf filter only supports equality restriction');
  });

  it('rejects the inferred subfilter with not_eq operator', async () => {
    const filter = makeRegardingOfFilter([
      { key: 'relationship_type', values: ['targets'] },
      { key: 'is_inferred', values: ['true'] },
    ], FilterOperator.NotEq);
    await expect(adaptFilterToRegardingOfFilterKey(CONTEXT, USER, filter))
      .rejects.toThrow('regardingOf filter with inferred subfilter only supports eq operator');
  });

  it('rejects PIR relationship type for a user without PIR capability', async () => {
    const filter = makeRegardingOfFilter([{ key: 'relationship_type', values: [RELATION_IN_PIR] }]);
    await expect(adaptFilterToRegardingOfFilterKey(CONTEXT, USER, filter))
      .rejects.toThrow('You are not allowed to use PIR filtering');
  });
});

describe('adaptFilterToRegardingOfFilterKey — filter building', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('checks the existence of the relationship types when no id is given', async () => {
    const filter = makeRegardingOfFilter([{ key: 'relationship_type', values: ['targets', 'uses'] }]);
    const { newFilterGroup } = await adaptFilterToRegardingOfFilterKey(CONTEXT, USER, filter);

    expect(newFilterGroup.mode).toEqual(FilterMode.Or);
    expect(newFilterGroup.filters).toEqual([
      expect.objectContaining({ key: [buildRefRelationKey('targets', '*')], values: ['EXISTS'] }),
      expect.objectContaining({ key: [buildRefRelationKey('uses', '*')], values: ['EXISTS'] }),
    ]);
  });

  it('keeps only the ids the user has access to', async () => {
    vi.spyOn(engineModule, 'elFindByIds').mockResolvedValue([{ id: 'id-1', entity_type: 'Malware' }] as any);
    const filter = makeRegardingOfFilter([
      { key: 'id', values: ['id-1', 'id-2'] },
      { key: 'relationship_type', values: ['targets'] },
    ]);
    const { newFilterGroup } = await adaptFilterToRegardingOfFilterKey(CONTEXT, USER, filter);

    expect(newFilterGroup.filters).toEqual([
      expect.objectContaining({
        key: [buildRefRelationKey('targets', ID_INTERNAL), buildRefRelationKey('targets', ID_INFERRED)],
        values: ['id-1'],
      }),
    ]);
  });

  it('keeps all the ids when noRegardingOfFilterIdsCheck is set, with and mode for not_eq', async () => {
    vi.spyOn(engineModule, 'elFindByIds').mockResolvedValue([{ id: 'id-1', entity_type: 'Malware' }] as any);
    const filter = makeRegardingOfFilter([
      { key: 'id', values: ['id-1', 'id-2'] },
      { key: 'relationship_type', values: ['targets'] },
    ], FilterOperator.NotEq);
    const { newFilterGroup } = await adaptFilterToRegardingOfFilterKey(CONTEXT, USER, filter, true);

    expect(newFilterGroup.mode).toEqual(FilterMode.And);
    expect(newFilterGroup.filters).toEqual([
      expect.objectContaining({ values: ['id-1', 'id-2'], operator: FilterOperator.NotEq, mode: FilterMode.And }),
    ]);
  });

  it('rejects the query when none of the ids is accessible', async () => {
    vi.spyOn(engineModule, 'elFindByIds').mockResolvedValue([] as any);
    const filter = makeRegardingOfFilter([{ key: 'id', values: ['id-1'] }]);
    await expect(adaptFilterToRegardingOfFilterKey(CONTEXT, USER, filter))
      .rejects.toThrow('Specified ids not found or restricted');
  });

  it('rejects PIR ids without relationship type for a user without PIR capability', async () => {
    vi.spyOn(engineModule, 'elFindByIds').mockResolvedValue([{ id: 'pir-1', entity_type: ENTITY_TYPE_PIR }] as any);
    const filter = makeRegardingOfFilter([{ key: 'id', values: ['pir-1'] }]);
    await expect(adaptFilterToRegardingOfFilterKey(CONTEXT, USER, filter))
      .rejects.toThrow('You are not allowed to use PIR filtering');
  });
});
