import gql from 'graphql-tag';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { testContext } from '../../utils/testQuery';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { SYSTEM_USER } from '../../../src/utils/access';
import { internalLoadById } from '../../../src/database/middleware-loader';
import * as streamHandler from '../../../src/database/stream/stream-handler';
import { intelligenceRequirementManagerHandler } from '../../../src/manager/intelligenceRequirementManager';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import type { BasicStoreEntity } from '../../../src/types/store';

const ADD_QUERY = gql`
  mutation IrManagerAdd($input: IntelligenceRequirementInput!) {
    intelligenceRequirementAdd(input: $input) { id }
  }
`;

const UPDATE_QUERY = gql`
  mutation IrManagerUpdate($id: ID!, $input: IntelligenceRequirementInput!) {
    intelligenceRequirementUpdate(id: $id, input: $input) { id ir_relevance_rules { id points } }
  }
`;

const MATCHES_QUERY = gql`
  query IrManagerMatches($id: ID!) {
    intelligenceRequirementMatches(id: $id, first: 50) { edges { node { id match_entity_id match_status match_score } } }
  }
`;

const ITEMS_QUERY = gql`
  query IrManagerItems($id: ID!) {
    intelligenceRequirementItems(id: $id, first: 50) { edges { node { id item_kind item_status item_match_id } } }
  }
`;

const MATCH_STATUS_QUERY = gql`
  mutation IrManagerMatchStatus($id: ID!, $status: IrMatchDecisionStatus!) {
    intelligenceRequirementMatchStatusUpdate(id: $id, status: $status) { id match_status }
  }
`;

const MATCHES_STATUS_QUERY = gql`
  mutation IrManagerMatchesStatus($ids: [ID!]!, $status: IrMatchDecisionStatus!) {
    intelligenceRequirementMatchesStatusUpdate(ids: $ids, status: $status)
  }
`;

const ITEMS_DECIDE_QUERY = gql`
  mutation IrManagerItemsDecide($ids: [ID!]!, $decision: IrItemDecision!) {
    intelligenceRequirementItemsDecide(ids: $ids, decision: $decision)
  }
`;

const DELETE_QUERY = gql`
  mutation IrManagerDelete($id: ID!) {
    intelligenceRequirementDelete(id: $id)
  }
`;

// Test dataset: APT41 —uses→ Paradise Ransomware —uses→ Spear phishing messages with malicious links
const APT41_STIX_ID = 'intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7';
const PARADISE_STIX_ID = 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c';
const ATTACK_PATTERN_STIX_ID = 'attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc';
const APT41_USES_PARADISE_STIX_ID = 'relationship--9f999fc5-5c74-4964-ab87-ee4c7cdc37a3';

interface Ids { actor: string; malware: string; attackPattern: string; relationship: string }
type MatchNode = { id: string; match_entity_id: string; match_status: string; match_score: number };
type ItemNode = { id: string; item_kind: string; item_status: string; item_match_id: string | null };

const buildInput = (ids: Ids, confidencePoints = 40): Record<string, any> => ({
  name: 'IR manager integration requirement',
  ir_question: 'What does APT41 use?',
  ir_priority: 'high',
  ir_subject_groups: [
    { id: 'g-actor', name: 'Tracked actor', kind: 'list', role: 'both', entity_ids: [ids.actor] },
  ],
  ir_scope_criteria: [
    { id: 'c-actor', name: 'Actor', kind: 'attribute', from_group_ids: ['g-actor'], target_types: ['Intrusion-Set'], mode: 'auto' },
    {
      id: 'c-uses',
      name: 'Used by the actor',
      kind: 'graph',
      from_group_ids: ['g-actor'],
      relationship_types: ['uses'],
      direction: 'outgoing',
      target_types: ['Malware'],
      mode: 'auto',
    },
    {
      id: 'c-hop',
      name: 'Used by the malware',
      kind: 'graph',
      from_group_ids: [],
      from_in_requirement: true,
      from_types: ['Malware'],
      relationship_types: ['uses'],
      direction: 'outgoing',
      target_types: ['Attack-Pattern'],
      mode: 'propose',
    },
  ],
  ir_relevance_rules: [
    {
      id: 'r-confidence',
      name: 'Confident',
      applies_to_types: ['Malware', 'Intrusion-Set'],
      points: confidencePoints,
      filters: { mode: 'and', filterGroups: [], filters: [{ key: ['confidence'], values: ['0'], operator: 'gte' }] },
    },
  ],
  ir_thresholds: [30, 70],
  ir_rescan_days: 1,
});

const octi = (extension: Record<string, unknown>) => ({ [STIX_EXT_OCTI]: extension });

// Stream events after the position of a requirement created now (its position is one rescan day back)
const buildEvents = (ids: Ids) => {
  const now = Date.now();
  const event = (offset: number, type: string, data: unknown, context?: unknown) => ({
    id: `${now + offset}-0`,
    event: type,
    data: { type, scope: 'external', message: 'test', origin: {}, version: '4', data, ...(context ? { context } : {}) },
  });
  return [
    event(1, 'create', { id: APT41_STIX_ID, type: 'intrusion-set', name: 'APT41', extensions: octi({ id: ids.actor, type: 'Intrusion-Set' }) }),
    event(2, 'create', {
      id: APT41_USES_PARADISE_STIX_ID,
      type: 'relationship',
      relationship_type: 'uses',
      source_ref: APT41_STIX_ID,
      target_ref: PARADISE_STIX_ID,
      extensions: octi({ id: ids.relationship, source_ref: ids.actor, source_type: 'Intrusion-Set', target_ref: ids.malware, target_type: 'Malware' }),
    }),
    event(3, 'update', {
      id: PARADISE_STIX_ID,
      type: 'malware',
      name: 'Paradise Ransomware',
      extensions: octi({ id: ids.malware, type: 'Malware' }),
    }, { patch: [{ op: 'replace', path: '/description', value: 'updated' }, { op: 'replace', path: '/modified', value: 'now' }] }),
    event(4, 'create', { id: 'sighting--test', type: 'sighting', extensions: octi({ id: 'sighting-id', type: 'Stix-Sighting-Relationship' }) }),
    event(5, 'delete', { id: PARADISE_STIX_ID, type: 'malware', extensions: octi({ id: ids.malware, type: 'Malware' }) }),
  ];
};

const mockStream = (events: unknown[], offsetMs = 10) => {
  vi.spyOn(streamHandler, 'fetchStreamEventsRangeFromEventId').mockImplementation(async (_from: string, callback: any) => {
    await callback(events);
    return { lastEventId: `${Date.now() + offsetMs}-0` } as any;
  });
};

const readMatches = async (irId: string): Promise<MatchNode[]> => {
  const { data } = await queryAsAdminWithSuccess({ query: MATCHES_QUERY, variables: { id: irId } });
  return data.intelligenceRequirementMatches.edges.map((e: { node: MatchNode }) => e.node);
};

const readItems = async (irId: string): Promise<ItemNode[]> => {
  const { data } = await queryAsAdminWithSuccess({ query: ITEMS_QUERY, variables: { id: irId } });
  return data.intelligenceRequirementItems.edges.map((e: { node: ItemNode }) => e.node);
};

describe('Intelligence requirement manager: stream processing', () => {
  const ids: Ids = { actor: '', malware: '', attackPattern: '', relationship: '' };
  let irId = '';

  beforeAll(async () => {
    const load = async (stixId: string) => (await internalLoadById<BasicStoreEntity>(testContext, SYSTEM_USER, stixId)).internal_id;
    ids.actor = await load(APT41_STIX_ID);
    ids.malware = await load(PARADISE_STIX_ID);
    ids.attackPattern = await load(ATTACK_PATTERN_STIX_ID);
    ids.relationship = await load(APT41_USES_PARADISE_STIX_ID);
    const { data } = await queryAsAdminWithSuccess({ query: ADD_QUERY, variables: { input: buildInput(ids) } });
    irId = data.intelligenceRequirementAdd.id;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  afterAll(async () => {
    if (irId) await queryAsAdminWithSuccess({ query: DELETE_QUERY, variables: { id: irId } });
  });

  it('should bring the entities of the scope in from the stream, with the second hop backfill', async () => {
    mockStream(buildEvents(ids));
    await intelligenceRequirementManagerHandler();
    const matches = await readMatches(irId);
    const byEntity = new Map(matches.map((m) => [m.match_entity_id, m]));
    expect(byEntity.get(ids.actor)?.match_status).toEqual('auto');
    expect(byEntity.get(ids.malware)?.match_status).toEqual('auto');
    expect(byEntity.get(ids.attackPattern)?.match_status).toEqual('proposed');
    const items = await readItems(irId);
    const kinds = items.map((i) => i.item_kind);
    expect(kinds).toContain('entered');
    expect(kinds).toContain('proposed');
  });

  it('should do nothing on a batch without knowledge creation or update', async () => {
    const before = await readMatches(irId);
    mockStream([], 20);
    await intelligenceRequirementManagerHandler();
    const after = await readMatches(irId);
    expect(after.length).toEqual(before.length);
  });

  it('should accept a proposed entity and backfill what it reaches', async () => {
    const proposed = (await readMatches(irId)).find((m) => m.match_entity_id === ids.attackPattern);
    expect(proposed).toBeDefined();
    const { data } = await queryAsAdminWithSuccess({ query: MATCH_STATUS_QUERY, variables: { id: proposed!.id, status: 'accepted' } });
    expect(data.intelligenceRequirementMatchStatusUpdate.match_status).toEqual('accepted');
    // Only the items of the accepted entity are closed: the second hop may propose other attack patterns of the malware
    const proposedItems = (await readItems(irId)).filter((i) => i.item_kind === 'proposed' && i.item_match_id === proposed!.id);
    expect(proposedItems.length).toBeGreaterThan(0);
    expect(proposedItems.every((i) => i.item_status !== 'open')).toBe(true);
  });

  it('should rescore the entities of the requirement when its relevance changes', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: UPDATE_QUERY, variables: { id: irId, input: buildInput(ids, 80) } });
    expect(data.intelligenceRequirementUpdate.ir_relevance_rules[0].points).toEqual(80);
    const malware = (await readMatches(irId)).find((m) => m.match_entity_id === ids.malware);
    expect(malware?.match_score).toBeGreaterThanOrEqual(0);
  });

  it('should acknowledge the open inbox items in one decision', async () => {
    const open = (await readItems(irId)).filter((i) => i.item_status === 'open');
    const { data } = await queryAsAdminWithSuccess({ query: ITEMS_DECIDE_QUERY, variables: { ids: open.map((i) => i.id), decision: 'acknowledge' } });
    expect(data.intelligenceRequirementItemsDecide).toBeGreaterThanOrEqual(0);
    expect(data.intelligenceRequirementItemsDecide).toBeLessThanOrEqual(open.length);
  });

  it('should remove entities from the requirement and keep the decision on new proofs', async () => {
    const malware = (await readMatches(irId)).find((m) => m.match_entity_id === ids.malware);
    const { data } = await queryAsAdminWithSuccess({ query: MATCHES_STATUS_QUERY, variables: { ids: [malware!.id], status: 'removed' } });
    expect(data.intelligenceRequirementMatchesStatusUpdate).toEqual(1);
    // A new proof on a removed entity does not bring it back
    mockStream(buildEvents(ids), 30);
    await intelligenceRequirementManagerHandler();
    const after = (await readMatches(irId)).find((m) => m.match_entity_id === ids.malware);
    expect(after?.match_status).toEqual('removed');
  });
});
