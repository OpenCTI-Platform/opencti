import { beforeEach, describe, expect, it, vi } from 'vitest';

// ── Infrastructure stubs ─────────────────────────────────────────────────────
// Only the Elasticsearch accesses are stubbed: the loader itself
// (loadElementsWithDependencies / loadElementMetaDependencies) runs for real.

vi.mock('../../../src/database/engine');
vi.mock('../../../src/database/middleware-loader', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/middleware-loader')>();
  return { ...actual, fullRelationsList: vi.fn() };
});
vi.mock('../../../src/database/redis', () => ({ notify: vi.fn(), redisAddDeletions: vi.fn() }));
vi.mock('../../../src/database/cache', () => ({
  getEntitiesMapFromCache: vi.fn(),
  getEntityFromCache: vi.fn(),
}));
vi.mock('../../../src/database/stream/stream-handler', () => ({
  storeCreateEntityEvent: vi.fn(),
  storeCreateRelationEvent: vi.fn(),
  storeDeleteEvent: vi.fn(),
  storeMergeEvent: vi.fn(),
  storeUpdateEvent: vi.fn(),
}));
vi.mock('../../../src/database/file-search', () => ({
  elUpdateRemovedFiles: vi.fn(),
}));
vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));
vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return {
    ...(actual as object),
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
    extendedErrors: false,
    BUS_TOPICS: {},
  };
});

// ── Imports (after mocks) ────────────────────────────────────────────────────

import '../../../src/modules/index';
import { registerModules } from '../../../src/composition-root';
import { elFindByIds } from '../../../src/database/engine';
import { fullRelationsList } from '../../../src/database/middleware-loader';
import { storeLoadByIdsWithRefs } from '../../../src/database/middleware';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import { RELATION_CREATED_BY, RELATION_OBJECT, RELATION_OBJECT_MARKING } from '../../../src/schema/stixRefRelationship';

registerModules();

const context = {} as any;
const user = { id: 'user-id' } as any;

const REPORT = {
  _index: 'opencti_stix_domain_objects-000001',
  id: 'report-id',
  internal_id: 'report-id',
  standard_id: 'report--f3e554eb-3e8b-5b1e-b7e8-6f1e1b8a7c11',
  entity_type: 'Report',
  base_type: 'ENTITY',
  parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Container'],
  name: 'Report',
  published: '2026-10-13T22:19:00.000Z',
  created: '2026-10-13T22:19:00.000Z',
  modified: '2026-10-13T22:19:00.000Z',
};
const AUTHOR_ID = 'author-id';
const MARKING_ID = 'marking-id';
const MEMBER_IDS = ['member-1', 'member-2', 'member-3'];

// The author is also a member of the report: it must keep its full data
const ref = (entityType: string, toId: string, toType: string) => ({
  _index: 'opencti_stix_meta_relationships-000001',
  id: `${entityType}-${toId}`,
  internal_id: `${entityType}-${toId}`,
  entity_type: entityType,
  base_type: 'RELATION',
  fromId: REPORT.internal_id,
  toId,
  toType,
});
const RELATIONS = [
  ref(RELATION_CREATED_BY, AUTHOR_ID, 'Organization'),
  ref(RELATION_OBJECT_MARKING, MARKING_ID, 'Marking-Definition'),
  ...MEMBER_IDS.map((id) => ref(RELATION_OBJECT, id, 'Malware')),
  ref(RELATION_OBJECT, AUTHOR_ID, 'Organization'),
];

const target = (id: string, entityType: string, baseData: boolean) => {
  const base = { _index: 'opencti_stix_domain_objects-000001', id, internal_id: id, standard_id: `${entityType.toLowerCase()}--${id}`, entity_type: entityType, base_type: 'ENTITY' };
  return baseData ? base : { ...base, name: `name of ${id}`, description: `long description of ${id}` };
};
const typeOf = (id: string) => (id === AUTHOR_ID ? 'Organization' : id === MARKING_ID ? 'Marking-Definition' : 'Malware');

describe('storeLoadByIdsWithRefs on a container', () => {
  beforeEach(() => {
    vi.mocked(fullRelationsList).mockReset();
    vi.mocked(fullRelationsList).mockImplementation(async (_context, _user, _types, opts: any) => {
      await opts.callback(RELATIONS);
      return [];
    });
    vi.mocked(elFindByIds).mockReset();
    vi.mocked(elFindByIds).mockImplementation(async (_context, _user, ids: any, opts: any = {}) => {
      if (!opts.toMap) {
        return [REPORT] as any;
      }
      return Object.fromEntries((ids as string[]).map((id) => [id, target(id, typeOf(id), opts.baseData === true)])) as any;
    });
  });

  const targetLoads = () => vi.mocked(elFindByIds).mock.calls
    .filter(([, , , opts]) => (opts as any)?.toMap)
    .map(([, , ids, opts]) => ({ ids: [...(ids as string[])].sort(), baseData: (opts as any).baseData }));

  it('should load all the members with their full data by default', async () => {
    const [report] = await storeLoadByIdsWithRefs(context, user, [REPORT.internal_id]) as any[];
    expect(targetLoads()).toEqual([{ ids: [AUTHOR_ID, MARKING_ID, ...MEMBER_IDS].sort(), baseData: false }]);
    expect(report.objects.find((o: any) => o.internal_id === 'member-1').description).toBeDefined();
  });

  it('should load the members with their base data only with objectsBaseData', async () => {
    const [report] = await storeLoadByIdsWithRefs(context, user, [REPORT.internal_id], { objectsBaseData: true }) as any[];
    // Members that are only members are not hydrated, the author and the marking are
    expect(targetLoads()).toEqual([
      { ids: [AUTHOR_ID, MARKING_ID].sort(), baseData: false },
      { ids: [...MEMBER_IDS].sort(), baseData: true },
    ]);
    const member = report.objects.find((o: any) => o.internal_id === 'member-1');
    expect(member.standard_id).toBe('malware--member-1');
    expect(member.description).toBeUndefined();
    expect(report.objects).toHaveLength(MEMBER_IDS.length + 1);
    expect(report.createdBy.description).toBeDefined();
    expect(report.objects.find((o: any) => o.internal_id === AUTHOR_ID).description).toBeDefined();
  });

  it('should produce the same STIX with and without objectsBaseData', async () => {
    const [full] = await storeLoadByIdsWithRefs(context, user, [REPORT.internal_id]) as any[];
    const [base] = await storeLoadByIdsWithRefs(context, user, [REPORT.internal_id], { objectsBaseData: true }) as any[];
    const fullStix = convertStoreToStix_2_1(full) as any;
    expect(fullStix.object_refs).toHaveLength(MEMBER_IDS.length + 1);
    expect(convertStoreToStix_2_1(base)).toEqual(fullStix);
  });
});
