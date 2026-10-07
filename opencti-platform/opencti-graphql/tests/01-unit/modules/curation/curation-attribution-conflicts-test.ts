import { beforeEach, describe, expect, it, vi } from 'vitest';
import { commitRotationCursors, findAttributionConflictDrafts as findDrafts, rotationCursors } from '../../../../src/modules/curation/curation-scan';
import { pageEntitiesConnection } from '../../../../src/database/middleware-loader';
import type { AuthContext } from '../../../../src/types/user';

const state = vi.hoisted(() => ({ relations: [] as Array<Record<string, unknown>>, redis: {} as Record<string, string> }));
const CURSOR_KEY = 'curation_scan_rotation_distinct_pairs';

// A campaign attributed to three actors: A and B were decided distinct, B and C too, A and C never were.
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  pageEntitiesConnection: vi.fn(async () => ({
    edges: [{ node: { subject_ids: ['actor-a', 'actor-b'] } }, { node: { subject_ids: ['actor-b', 'actor-c'] } }],
    pageInfo: { hasNextPage: false },
  })),
  fullRelationsList: vi.fn(async (_context: unknown, _user: unknown, _type: unknown, opts: { callback: (relations: unknown[]) => Promise<void> }) => {
    await opts.callback(state.relations);
    return [];
  }),
  internalFindByIds: vi.fn(async (_context: unknown, _user: unknown, ids: string[]) => Object.fromEntries(
    ids.map((id) => [id, { entity_type: id === 'campaign' ? 'Campaign' : 'Intrusion-Set', name: id }]),
  )),
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisGetManagerEventState: vi.fn(async (key: string) => state.redis[key] ?? null),
  redisSetManagerEventState: vi.fn(async (key: string, value: string) => {
    state.redis[key] = value;
  }),
}));

const findAttributionConflictDrafts = (context: AuthContext) => findDrafts(context, rotationCursors());

const attribution = (actor: string, id: string, author?: string) => ({
  fromId: 'campaign',
  toId: actor,
  internal_id: id,
  ...(author ? { 'created-by': author } : {}),
});

type Relationships = Array<{ actor_id: string; relationship_id: string }>;
const pairsOf = (drafts: Awaited<ReturnType<typeof findAttributionConflictDrafts>>) => drafts
  .map((draft) => (draft.action_payload as { relationships: Relationships }).relationships);

describe('attribution conflicts', () => {
  beforeEach(() => {
    state.relations = [];
    state.redis = {};
  });

  it('raises one proposal per pair decided distinct, so resolving one never removes an attribution of another pair', async () => {
    state.relations = [
      attribution('actor-a', 'rel-a', 'source-1'),
      attribution('actor-b', 'rel-b', 'source-2'),
      attribution('actor-b', 'rel-b-2', 'source-2'),
      attribution('actor-c', 'rel-c', 'source-3'),
    ];
    const drafts = await findAttributionConflictDrafts({} as never);
    expect(pairsOf(drafts)).toEqual([
      [{ actor_id: 'actor-a', relationship_id: 'rel-a' }, { actor_id: 'actor-b', relationship_id: 'rel-b' }, { actor_id: 'actor-b', relationship_id: 'rel-b-2' }],
      [{ actor_id: 'actor-b', relationship_id: 'rel-b' }, { actor_id: 'actor-b', relationship_id: 'rel-b-2' }, { actor_id: 'actor-c', relationship_id: 'rel-c' }],
    ]);
    // An actor attributed twice is one subject of its proposal.
    expect(drafts.map((draft) => draft.subjects.map((subject) => subject.id))).toEqual([
      ['campaign', 'actor-a', 'actor-b'],
      ['campaign', 'actor-b', 'actor-c'],
    ]);
    // The authors decide the conflict but are never named: a reader of the proposal may not be allowed to read them.
    expect(drafts[0].evidence[0].description).toBe(
      '"campaign" is attributed to "actor-a" and to "actor-b": these actors were decided to be distinct and no source attributes it to both',
    );
    expect(JSON.parse(drafts[0].evidence[0].details as unknown as string)).not.toHaveProperty('author_names');
    expect(drafts[0].evidence[0].details).not.toContain('source-1');
  });

  it('keeps a co-attribution a source makes: distinct actors can share an attribution', async () => {
    state.relations = [
      attribution('actor-a', 'rel-a', 'source-1'),
      attribution('actor-b', 'rel-b', 'source-1'),
      attribution('actor-b', 'rel-b-2', 'source-2'),
      attribution('actor-c', 'rel-c', 'source-3'),
    ];
    // source-1 attributes the campaign to A and B: only B and C, which no source names together, conflict.
    expect(pairsOf(await findAttributionConflictDrafts({} as never))).toEqual([
      [{ actor_id: 'actor-b', relationship_id: 'rel-b' }, { actor_id: 'actor-b', relationship_id: 'rel-b-2' }, { actor_id: 'actor-c', relationship_id: 'rel-c' }],
    ]);
  });

  it('takes an attribution without an author as no evidence of a conflict', async () => {
    state.relations = [
      attribution('actor-a', 'rel-a'),
      attribution('actor-b', 'rel-b', 'source-2'),
      attribution('actor-c', 'rel-c'),
    ];
    expect(await findAttributionConflictDrafts({} as never)).toEqual([]);
  });

  it('reads the pairs decided distinct from where the previous scan stopped, and goes back to the start after the last page', async () => {
    const page = vi.mocked(pageEntitiesConnection);
    page.mockResolvedValueOnce({ edges: [], pageInfo: { hasNextPage: true, endCursor: 'cursor-2' } } as never);
    state.redis[CURSOR_KEY] = 'cursor-1';
    const cursors = rotationCursors();
    await findDrafts({} as never, cursors);
    expect((page.mock.calls.at(-1)?.[3] as { after?: string }).after).toBe('cursor-1');
    await commitRotationCursors(cursors);
    expect(state.redis[CURSOR_KEY]).toBe('cursor-2');
    await findDrafts({} as never, cursors);
    expect((page.mock.calls.at(-1)?.[3] as { after?: string }).after).toBe('cursor-2');
    await commitRotationCursors(cursors);
    expect(state.redis[CURSOR_KEY]).toBe('');
  });
});
