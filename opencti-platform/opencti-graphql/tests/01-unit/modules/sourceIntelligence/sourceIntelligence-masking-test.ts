import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { BasicStoreEntitySource, SourceKindValue } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';
import {
  ENTITY_TYPE_SOURCE,
  ENTITY_TYPE_SOURCE_RECOMMENDATION,
  SOURCE_KIND_AUTHOR,
  SOURCE_KIND_CONNECTOR,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';
import { BUS_TOPICS, getBusTopicForEntityType } from '../../../../src/config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../../src/schema/general';

const { cachedSources, accessibleIdentities, listedSources } = vi.hoisted(() => ({
  cachedSources: new Map<string, unknown>(),
  accessibleIdentities: new Set<string>(),
  listedSources: { calls: 0 },
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesMapFromCache: vi.fn(async () => cachedSources),
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  notify: vi.fn(async (_topic: string, instance: unknown) => instance),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(async (_context: unknown, _user: unknown, ids: string[]) => ids
    .filter((id) => accessibleIdentities.has(id))
    .map((id) => ({ internal_id: id }))),
  // The stored author sources, as the query on their kind returns them
  fullEntitiesList: vi.fn(async () => {
    listedSources.calls += 1;
    return [...cachedSources.values()].filter((source) => (source as BasicStoreEntitySource).source_kind === SOURCE_KIND_AUTHOR);
  }),
}));

const {
  maskRestrictedNames,
  maskRestrictedSources,
  notifySourceEdition,
  recordNamedAuthors,
  restrictedRecommendationNames,
  sourceAuditName,
  sourceCostActivity,
  sourceEditActivityInput,
  sourceRestrictions,
  withoutRestrictedScorecards,
  withoutRestrictedSourceEntries,
  withoutRestrictedSources,
} = await import('../../../../src/modules/sourceIntelligence/sourceIntelligence-domain');
const { notify } = await import('../../../../src/database/redis');

const user = { id: 'analyst' } as AuthUser;
const authorSource = (id: string, refId: string, name: string) => ({ internal_id: id, source_kind: SOURCE_KIND_AUTHOR, ref_id: refId, name }) as BasicStoreEntitySource;
const recorded = (...authors: Array<[string, string]>) => JSON.stringify(authors.map(([ref_id, name]) => ({ ref_id, name })));
// Each request has its own context: the resolution is shared by the fields of one request only
const newContext = () => ({}) as AuthContext;

describe('Source intelligence recommendation masking', () => {
  beforeEach(() => {
    cachedSources.clear();
    accessibleIdentities.clear();
  });

  it('should mask the name a recommendation was written with after the author was renamed', async () => {
    cachedSources.set('source-1', authorSource('source-1', 'identity-1', 'Acme Threat Research'));
    const recommendation = { internal_id: 'rec-1', source_id: 'source-1', payload: '{}', named_authors: recorded(['identity-1', 'Acme']) };
    const names = await restrictedRecommendationNames(newContext(), user, recommendation);
    expect(names.sort()).toEqual(['Acme', 'Acme Threat Research']);
    expect(maskRestrictedNames('Raise the confidence of Acme (now Acme Threat Research)', names))
      .toBe('Raise the confidence of Restricted (now Restricted)');
  });

  it('should mask a name whatever its case, reading the characters of the name literally', () => {
    expect(maskRestrictedNames('Dismissed: ACME threat research and acme overlap, A.C.M.E. (EU) too', ['Acme', 'Acme Threat Research', 'A.C.M.E. (EU)', '']))
      .toBe('Dismissed: Restricted and Restricted overlap, Restricted too');
    expect(maskRestrictedNames('ABC stays', ['A.C'])).toBe('ABC stays');
  });

  it('should keep masking the recorded names once the source is no longer tracked', async () => {
    const recommendation = { internal_id: 'rec-1', source_id: 'source-1', payload: '{"peer_source_id":"source-2"}', named_authors: recorded(['identity-1', 'Acme'], ['identity-2', 'Globex']) };
    expect((await restrictedRecommendationNames(newContext(), user, recommendation)).sort()).toEqual(['Acme', 'Globex']);
  });

  it('should leave the names of accessible authors and of other source kinds visible', async () => {
    accessibleIdentities.add('identity-1');
    cachedSources.set('source-1', authorSource('source-1', 'identity-1', 'Acme'));
    cachedSources.set('source-2', { internal_id: 'source-2', source_kind: SOURCE_KIND_CONNECTOR, ref_id: 'connector-1', name: 'MISP' });
    const recommendation = { internal_id: 'rec-1', source_id: 'source-1', payload: '{"peer_source_id":"source-2"}', named_authors: recorded(['identity-1', 'Acme']) };
    expect(await restrictedRecommendationNames(newContext(), user, recommendation)).toEqual([]);
  });

  it('should mask the current name of a recommendation that recorded no author', async () => {
    cachedSources.set('source-1', authorSource('source-1', 'identity-1', 'Acme'));
    expect(await restrictedRecommendationNames(newContext(), user, { internal_id: 'rec-1', source_id: 'source-1', payload: '{}' })).toEqual(['Acme']);
  });

  it('should record the current names next to the recorded ones, the given sources first', async () => {
    cachedSources.set('source-1', authorSource('source-1', 'identity-1', 'Acme (cached)'));
    cachedSources.set('source-2', authorSource('source-2', 'identity-2', 'Globex'));
    const stored = await recordNamedAuthors(
      newContext(),
      { source_id: 'source-1', payload: '{"peer_source_id":"source-2"}', named_authors: recorded(['identity-1', 'Acme']) },
      [authorSource('source-1', 'identity-1', 'Acme Threat Research')],
    );
    expect(JSON.parse(stored)).toEqual([
      { ref_id: 'identity-1', name: 'Acme' },
      { ref_id: 'identity-1', name: 'Acme Threat Research' },
      { ref_id: 'identity-2', name: 'Globex' },
    ]);
  });

  it('should record nothing for a recommendation without author source', async () => {
    expect(await recordNamedAuthors(newContext(), { source_id: null, payload: '{"collection_gap_id":"gap-1"}' })).toBe('[]');
  });
});

describe('Source intelligence authors the user cannot access', () => {
  const connector = { internal_id: 'source-3', source_kind: SOURCE_KIND_CONNECTOR, ref_id: 'connector-1', name: 'IP reputation feed' } as BasicStoreEntitySource;
  const share = (sourceId: string) => ({ source_id: sourceId, shared_count: 5, share: 0.5 });
  const scorecard = (sourceId: string, sourceKind: SourceKindValue, overlap: Array<ReturnType<typeof share>> = []) => ({ source_id: sourceId, source_kind: sourceKind, overlap });

  beforeEach(() => {
    cachedSources.clear();
    accessibleIdentities.clear();
    listedSources.calls = 0;
    cachedSources.set('source-1', authorSource('source-1', 'identity-1', 'Restricted CERT'));
    cachedSources.set('source-2', authorSource('source-2', 'identity-2', 'Acme'));
    cachedSources.set('source-3', connector);
    accessibleIdentities.add('identity-2');
  });

  it('should leave out the scorecards of such an author, of a removed author, and the overlap entries naming one', async () => {
    const readable = await withoutRestrictedScorecards(newContext(), user, [
      scorecard('source-1', SOURCE_KIND_AUTHOR, [share('source-2')]),
      scorecard('source-2', SOURCE_KIND_AUTHOR, [share('source-1'), share('source-3')]),
      scorecard('source-3', SOURCE_KIND_CONNECTOR, [share('source-1')]),
      scorecard('source-9', SOURCE_KIND_AUTHOR),
    ]);
    expect(readable).toEqual([
      scorecard('source-2', SOURCE_KIND_AUTHOR, [share('source-3')]),
      scorecard('source-3', SOURCE_KIND_CONNECTOR),
    ]);
  });

  it('should list its id among the ids a query leaves out, and resolve them once per request', async () => {
    const context = newContext();
    expect((await sourceRestrictions(context, user)).restrictedIds).toEqual(['source-1']);
    await withoutRestrictedSourceEntries(context, user, [share('source-1')]);
    expect(listedSources.calls).toBe(1);
  });

  it('should leave such an author out of the widget sources and of the coverage of a gap', async () => {
    const sources = [...cachedSources.values()] as BasicStoreEntitySource[];
    expect((await withoutRestrictedSources(newContext(), user, sources)).map((source) => source.internal_id)).toEqual(['source-2', 'source-3']);
    const covering = [share('source-1'), share('source-2'), share('source-3')];
    expect((await withoutRestrictedSourceEntries(newContext(), user, covering)).map((entry) => entry.source_id)).toEqual(['source-2', 'source-3']);
  });

  it('should name such an author Restricted, without its metrics, when it is reached by its id', async () => {
    const scored = {
      ...authorSource('source-1', 'identity-1', 'Restricted CERT'),
      ref_type: 'Organization',
      source_user_ids: ['user-1'],
      source_cost: { amount: 12000, currency: 'EUR', period: 'year' as const },
      tags: ['premium'],
      owner_id: 'user-2',
      latest_value_score: 87,
      latest_volume: 1200,
      enabled: true,
    };
    const [masked] = await maskRestrictedSources(newContext(), user, [scored]);
    expect(masked).toMatchObject({
      internal_id: 'source-1',
      name: 'Restricted',
      ref_id: '',
      ref_type: undefined,
      source_user_ids: [],
      source_cost: null,
      tags: [],
      owner_id: null,
      latest_value_score: null,
      latest_volume: null,
      enabled: true,
    });
    const accessible = { ...authorSource('source-2', 'identity-2', 'Acme'), latest_value_score: 64 };
    expect(await maskRestrictedSources(newContext(), user, [accessible])).toEqual([accessible]);
  });

  it('should publish an edited author source as stored, and return it Restricted to the user who edited it', async () => {
    vi.mocked(notify).mockClear();
    const stored = { ...authorSource('source-1', 'identity-1', 'Restricted CERT'), source_cost: { amount: 12000, currency: 'EUR', period: 'year' as const }, tags: ['premium'] };
    const returned = await notifySourceEdition(newContext(), user, stored);
    expect(notify).toHaveBeenCalledWith(BUS_TOPICS[ENTITY_TYPE_SOURCE].EDIT_TOPIC, stored, user);
    expect(returned).toMatchObject({ internal_id: 'source-1', name: 'Restricted', source_cost: null, tags: [] });
    const accessible = authorSource('source-2', 'identity-2', 'Acme');
    expect(await notifySourceEdition(newContext(), user, accessible)).toEqual(accessible);
  });
});

describe('Source intelligence activity records', () => {
  it('should name an author source by its id only, since activity records are read without the author masking', () => {
    expect(sourceAuditName('source-1', authorSource('source-1', 'identity-1', 'Restricted CERT'))).toEqual('source `source-1`');
    expect(sourceAuditName('source-2', undefined)).toEqual('source `source-2`');
  });

  it('should name the other sources, whose names are never masked', () => {
    const connector = { internal_id: 'source-3', source_kind: SOURCE_KIND_CONNECTOR, ref_id: 'connector-1', name: 'IP reputation feed' } as BasicStoreEntitySource;
    expect(sourceAuditName('source-3', connector)).toEqual('source `IP reputation feed`');
  });

  it('should record the cost change of an author source without the cost, and the cost of the other sources', () => {
    const cost = { amount: 12000, currency: 'EUR', period: 'year' as const };
    const author = authorSource('source-1', 'identity-1', 'Restricted CERT');
    const connector = { internal_id: 'source-3', source_kind: SOURCE_KIND_CONNECTOR, ref_id: 'connector-1', name: 'IP reputation feed' } as BasicStoreEntitySource;
    const authorActivity = sourceCostActivity('source-1', author, cost);
    expect(authorActivity).toEqual({ message: 'sets the cost of source `source-1`', input: {} });
    expect(JSON.stringify(authorActivity)).not.toMatch(/12000|EUR|year/);
    expect(sourceCostActivity('source-1', author, null)).toEqual({ message: 'clears the cost of source `source-1`', input: { source_cost: null } });
    expect(sourceCostActivity('source-3', connector, cost)).toEqual({
      message: 'sets the cost of source `IP reputation feed` to 12000 EUR per year',
      input: { source_cost: cost },
    });
  });

  it('should record the edition of an author source with its state change only', () => {
    const patch = { description: 'Paid feed', tags: ['premium'], owner_id: 'user-2', enabled: false };
    expect(sourceEditActivityInput(authorSource('source-1', 'identity-1', 'Restricted CERT'), patch)).toEqual({ enabled: false });
    expect(sourceEditActivityInput(authorSource('source-1', 'identity-1', 'Restricted CERT'), { tags: ['premium'] })).toEqual({});
    expect(sourceEditActivityInput({ source_kind: SOURCE_KIND_CONNECTOR }, patch)).toEqual(patch);
  });
});

describe('Source intelligence edit events', () => {
  it('should publish the edits of sources and recommendations on their own topics, not on the generic internal object one', () => {
    const generic = BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC;
    [ENTITY_TYPE_SOURCE, ENTITY_TYPE_SOURCE_RECOMMENDATION].forEach((type) => {
      const topic = getBusTopicForEntityType(type)?.EDIT_TOPIC;
      expect(topic).toBeTruthy();
      expect(topic).not.toEqual(generic);
    });
  });
});
