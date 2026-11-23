// Cost of each primitive of the intelligence requirement engine, measured on the data of this platform (read-only,
// except the write measures which create and delete their own documents).
// Usage: yarn script:exec script-pir-cost
import '../src/modules/index';
import { logApp } from '../src/config/conf';
import { searchEngineInit } from '../src/database/engine';
import { redisInit } from '../src/database/redis';
import cacheManager from '../src/manager/cacheManager';
import { initLockFork } from '../src/lock/master-lock';
import { executionContext, SYSTEM_USER } from '../src/utils/access';
import { internalFindByIds, storeLoadById } from '../src/database/middleware-loader';
import { fetchStreamEventsRangeFromEventId, fetchStreamInfo } from '../src/database/stream/stream-handler';
import type { BasicStoreEntity } from '../src/types/store';
import { parsePir } from '../src/modules/pir/pir-utils';
import { type BasicStoreEntityPir, ENTITY_TYPE_PIR } from '../src/modules/pir/pir-types';
import type { ParsedIntelligenceRequirement, StoreIrCriterion, StoreIrSubjectGroup } from '../src/modules/intelligenceRequirement/intelligenceRequirement-types';
import type { BasicStoreEntityIntelligenceRequirementMatch } from '../src/modules/intelligenceRequirement/intelligenceRequirementMatch-types';
import {
  buildEngineState,
  evaluateCandidate,
  evaluateEntity,
  evaluateExistingRelationships,
  evaluateRelationship,
  findKeyword,
} from '../src/modules/intelligenceRequirement/intelligenceRequirement-engine';
import { computeMatchEligibility, computeMatchScore, createMatchWriter } from '../src/modules/intelligenceRequirement/intelligenceRequirement-scoring';
import { resetSubjectGroupCache, resolveSubjectGroup } from '../src/modules/intelligenceRequirement/intelligenceRequirement-groups';
import { deleteMatch, upsertMatch } from '../src/modules/intelligenceRequirement/intelligenceRequirementMatch-domain';
import { createItem } from '../src/modules/intelligenceRequirement/intelligenceRequirementItem-domain';
import { internalDeleteElementById } from '../src/database/middleware';
import { ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM } from '../src/modules/intelligenceRequirement/intelligenceRequirementItem-types';

const ES = 'http://localhost:9200';
const context = executionContext('pir_cost_benchmark');
const user = SYSTEM_USER;
const results: { step: string; label: string; n: number; median: number; p95: number; max: number; unit: string; note?: string }[] = [];

// region helpers
const es = async (index: string, body: unknown): Promise<any> => (await fetch(`${ES}/${index}/_search`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json();
const stats = (ms: number[]) => {
  const s = [...ms].sort((a, b) => a - b);
  const at = (q: number) => s[Math.min(s.length - 1, Math.floor(q * s.length))] ?? 0;
  return { n: s.length, median: at(0.5), p95: at(0.95), max: s[s.length - 1] ?? 0 };
};
const round = (v: number) => Math.round(v * 1000) / 1000;
const record = (step: string, label: string, ms: number[], unit = 'ms', note?: string) => {
  const st = stats(ms);
  results.push({ step, label, n: st.n, median: round(st.median), p95: round(st.p95), max: round(st.max), unit, note });
  logApp.info(`[PIR COST] ${step} | ${label} | n=${st.n} median=${round(st.median)} p95=${round(st.p95)} max=${round(st.max)} ${unit}${note ? ` | ${note}` : ''}`);
};
const time = async (fn: () => Promise<unknown>) => {
  const start = performance.now();
  await fn();
  return performance.now() - start;
};
const timeEach = async <T>(items: T[], fn: (item: T) => Promise<unknown>, reps = 2) => {
  const ms: number[] = [];
  for (let r = 0; r < reps; r += 1) {
    for (let i = 0; i < items.length; i += 1) ms.push(await time(() => fn(items[i])));
  }
  return ms;
};
const filter = (key: string, values: string[], operator = 'eq') => JSON.stringify({ mode: 'and', filters: [{ key: [key], values, operator, mode: 'or' }], filterGroups: [] });
const group = (id: string, kind: 'list' | 'filter', entityIds: string[], filters: string | null = null): StoreIrSubjectGroup => ({
  id, name: id, kind, role: 'context', entity_ids: entityIds, filters, keywords: [], exclude_keywords: [],
});
const criterion = (patch: Partial<StoreIrCriterion>): StoreIrCriterion => ({
  id: 'c', name: 'c', kind: 'attribute', from_group_ids: [], from_in_requirement: false, from_types: [], relationship_types: [], direction: 'outgoing',
  target_types: [], target_filters: null, keyword_fields: ['name', 'description', 'content'], mode: 'auto', conditions: [], ...patch,
} as StoreIrCriterion);
const requirement = (groups: StoreIrSubjectGroup[], criteria: StoreIrCriterion[], rules: unknown[] = []) => ({
  id: 'pir-cost-benchmark', ir_kiqs: [], ir_subject_groups: groups, ir_scope_criteria: criteria, ir_relevance_rules: rules, ir_thresholds: [30, 50, 70],
}) as unknown as ParsedIntelligenceRequirement;
const pseudo = (entity: { id: string; type: string }, criteriaIds: string[]) => ({
  match_entity_id: entity.id, match_entity_type: entity.type, match_criteria_ids: criteriaIds, match_status: 'auto',
}) as unknown as BasicStoreEntityIntelligenceRequirementMatch;

// Entities of a type, ranked by how many relationships of these types they have (to measure small and large fan-outs)
const byFanOut = async (types: string[], relationshipTypes: string[], role: string, size = 400) => {
  const rel = await es('*stix_core_relationships*,*stix_meta_relationships*', {
    size: 0,
    query: { terms: { 'relationship_type.keyword': relationshipTypes } },
    aggs: { n: { nested: { path: 'connections' }, aggs: { c: { terms: { field: 'connections.internal_id.keyword', size } } } } },
  });
  const counts = new Map<string, number>((rel.aggregations?.n?.c?.buckets ?? []).map((b: { key: string; doc_count: number }) => [b.key, b.doc_count]));
  const entities = await internalFindByIds<BasicStoreEntity>(context, user, Array.from(counts.keys())) as BasicStoreEntity[];
  return entities.filter((e) => types.includes(e.entity_type)).map((e) => ({ id: e.internal_id, type: e.entity_type, name: e.name, fanOut: counts.get(e.internal_id) ?? 0, role }))
    .sort((a, b) => b.fanOut - a.fanOut);
};
const sample = <T>(items: T[], count: number) => {
  if (items.length <= count) return items;
  const step = items.length / count;
  return Array.from({ length: count }, (_, i) => items[Math.floor(i * step)]);
};
const idsOf = async (index: string, query: unknown, size = 50) => ((await es(index, { size, _source: ['internal_id'], query })).hits?.hits ?? []).map((h: { _source: { internal_id: string } }) => h._source.internal_id);
// endregion

const run = async () => {
  // region data of this platform
  const stream = await fetchStreamInfo();
  const headMs = Number.parseInt((stream.lastEventId ?? '0-0').split('-')[0], 10);
  let events: any[] = [];
  let from = `${headMs - 4 * 24 * 3600 * 1000}-0`;
  while (events.length < 4000) {
    let batch: any[] = [];
    const { lastEventId } = await fetchStreamEventsRangeFromEventId(from, (read) => {
      batch = read;
    }, { streamBatchSize: 2000 });
    if (batch.length === 0 || lastEventId === from) break;
    events.push(...batch);
    from = lastEventId;
  }
  events = events.slice(0, 4000).map((e) => e.data).filter((e) => e.type === 'create' || e.type === 'update');
  const relationshipEvents = events.filter((e) => e.data?.type === 'relationship');
  const entityEvents = events.filter((e) => e.data?.type !== 'relationship' && e.data?.type !== 'sighting');
  logApp.info(`[PIR COST] stream sample: ${events.length} events (${relationshipEvents.length} relationships, ${entityEvents.length} entities)`);
  const v1Ids = await idsOf('*internal_objects*', { term: { 'entity_type.keyword': ENTITY_TYPE_PIR } }, 1);
  const v1 = v1Ids.length > 0 ? await storeLoadById<BasicStoreEntityPir>(context, user, v1Ids[0], ENTITY_TYPE_PIR) : null;
  const v1Targets: string[] = v1 ? parsePir(v1).pir_criteria.flatMap((c) => (c.filters.filters ?? []).filter((f) => (f.key as string[]).includes('toId')).flatMap((f) => f.values as string[])) : [];
  const threats = await byFanOut(['Intrusion-Set', 'Malware', 'Threat-Actor-Group', 'Campaign'], ['targets', 'uses'], 'threat');
  const vulnerabilities = await byFanOut(['Vulnerability'], ['exploits', 'has', 'object', 'targets', 'related-to'], 'vulnerability');
  const reports = await byFanOut(['Report'], ['object'], 'report');
  const regions = await idsOf('*stix_domain_objects*', { terms: { 'entity_type.keyword': ['Region'] } }, 30);
  const threatSample = sample(threats, 12);
  const vulnerabilitySample = sample(vulnerabilities, 12);
  const reportSample = sample(reports, 8);
  logApp.info(`[PIR COST] samples: ${threatSample.length} threats (fan-out ${threatSample[0]?.fanOut}→${threatSample[threatSample.length - 1]?.fanOut}), ${vulnerabilitySample.length} vulnerabilities, ${reportSample.length} reports`);
  // endregion

  // region 0. Reading the stream
  const readMs: number[] = [];
  for (let i = 0; i < 3; i += 1) {
    readMs.push(await time(() => fetchStreamEventsRangeFromEventId(`${headMs - 4 * 24 * 3600 * 1000}-0`, () => {}, { streamBatchSize: 2000 })));
  }
  record('0 stream', 'Read 2,000 events from the stream', readMs, 'ms per batch');
  // endregion

  // region 2. V2 basic: same PIR as V1 (relationship "targets" toward a list of targets), evaluation of the events
  const basicGroups = [group('g-targets', 'list', v1Targets.length > 0 ? v1Targets : regions.slice(0, 6))];
  const basicCriterion = criterion({ id: 'c-targets', kind: 'graph', from_group_ids: ['g-targets'], relationship_types: ['targets'], direction: 'incoming', target_types: ['Intrusion-Set', 'Malware', 'Threat-Actor', 'Campaign'] });
  const basic = requirement(basicGroups, [basicCriterion]);
  resetSubjectGroupCache();
  record('2 V2 basic', 'Engine state: resolve a list group (cold)', [await time(() => buildEngineState(context, user, basic))], 'ms per batch');
  const basicState = await buildEngineState(context, user, basic);
  {
    const ms: number[] = [];
    for (let r = 0; r < 3; r += 1) {
      const start = performance.now();
      for (let i = 0; i < relationshipEvents.length; i += 1) await evaluateRelationship(context, user, basicState, relationshipEvents[i].data);
      ms.push((performance.now() - start) / Math.max(1, relationshipEvents.length));
    }
    record('2 V2 basic', 'V2 evaluation of a relationship event (graph criterion, list group, no filter)', ms, 'ms per event');
  }
  {
    const withTargetFilter = requirement(basicGroups, [{ ...basicCriterion, target_filters: filter('confidence', ['50'], 'gte') }]);
    const state = await buildEngineState(context, user, withTargetFilter);
    const ms: number[] = [];
    const start = performance.now();
    for (let i = 0; i < relationshipEvents.length; i += 1) await evaluateRelationship(context, user, state, relationshipEvents[i].data);
    ms.push((performance.now() - start) / Math.max(1, relationshipEvents.length));
    record('2 V2 basic', 'Same, with a filter on the target (1 search query per matching candidate)', ms, 'ms per event');
  }
  // endregion

  // region 3. Subject groups: resolution of dynamic groups (cached 60 s), size-dependent
  const groupCases: [string, StoreIrSubjectGroup][] = [
    ['small dynamic group (Systems)', group('g-sys', 'filter', [], filter('entity_type', ['System']))],
    ['medium dynamic group (ransomware malware)', group('g-ransom', 'filter', [], filter('malware_types', ['ransomware']))],
    ['large dynamic group (every threat)', group('g-threats', 'filter', [], filter('entity_type', ['Malware', 'Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Campaign']))],
  ];
  for (let i = 0; i < groupCases.length; i += 1) {
    resetSubjectGroupCache();
    let size = 0;
    const ms = await time(async () => {
      size = (await resolveSubjectGroup(context, user, groupCases[i][1])).internalIds.length;
    });
    record('3 groups', `Resolve a ${groupCases[i][0]} (cold, then cached 60 s)`, [ms], 'ms per minute', `${size} members`);
  }
  // endregion

  // region 4. Scope conditions (and relevance rules: same primitives, same cost), one entity evaluated
  const europe = group('g-europe', 'list', regions);
  const threatsGroup = groupCases[2][1];
  const ransomware = groupCases[1][1];
  const conditionCases: { label: string; entities: typeof threatSample; ir: ParsedIntelligenceRequirement }[] = [
    {
      label: 'Filter on the entity (created in the last 6 months)',
      entities: vulnerabilitySample,
      ir: requirement([], [criterion({ id: 'k', target_types: ['Vulnerability'], conditions: [{ id: 'k1', name: 'recent', applies_to_types: [], filters: filter('created', ['now-6M'], 'gte'), link: null, path_condition: null }] })]),
    },
    {
      label: 'Link, 1 hop, to a small list group (targets a European region)',
      entities: threatSample,
      ir: requirement([europe], [criterion({ id: 'k', conditions: [{ id: 'k1', name: 'europe', applies_to_types: [], filters: null, link: { relationship_types: ['targets'], group_ids: ['g-europe'] }, path_condition: null }] })]),
    },
    {
      label: 'Link, 1 hop, to a medium dynamic group (uses a ransomware)',
      entities: threatSample,
      ir: requirement([ransomware], [criterion({ id: 'k', conditions: [{ id: 'k1', name: 'ransom', applies_to_types: [], filters: null, link: { relationship_types: ['uses'], group_ids: ['g-ransom'] }, path_condition: null }] })]),
    },
    {
      label: 'Link, 1 hop, to a large dynamic group (linked to any threat)',
      entities: vulnerabilitySample,
      ir: requirement([threatsGroup], [criterion({ id: 'k', conditions: [{ id: 'k1', name: 'threat', applies_to_types: [], filters: null, link: { relationship_types: ['exploits', 'targets', 'uses', 'related-to'], group_ids: ['g-threats'] }, path_condition: null }] })]),
    },
    {
      label: 'Container content: the report contains a threat (large group)',
      entities: reportSample,
      ir: requirement([threatsGroup], [criterion({ id: 'k', conditions: [{ id: 'k1', name: 'contains', applies_to_types: [], filters: null, link: { relationship_types: ['object'], group_ids: ['g-threats'] }, path_condition: null }] })]),
    },
    {
      label: 'Path, 2 hops: exploited by a threat that targets Europe',
      entities: vulnerabilitySample,
      ir: requirement([europe], [criterion({
        id: 'k',
        conditions: [{
          id: 'k1', name: 'path', applies_to_types: [], filters: null, link: null,
          path_condition: { relationship_types: ['exploits', 'targets'], direction: 'incoming', target_relationship_type: 'targets', target_ids: [], target_group_ids: ['g-europe'] },
        }],
      })]),
    },
  ];
  for (let i = 0; i < conditionCases.length; i += 1) {
    const { label, entities, ir } = conditionCases[i];
    await computeMatchEligibility(context, user, ir, pseudo(entities[0], ['k'])); // warms the group cache
    const ms = await timeEach(entities, (e) => computeMatchEligibility(context, user, ir, pseudo(e, ['k'])));
    record('4 conditions', label, ms, 'ms per entity', `fan-out ${entities[entities.length - 1]?.fanOut}→${entities[0]?.fanOut}`);
  }
  // A full PIR-02-like rescore: 1 condition and 7 rules
  {
    const systems = groupCases[0][1];
    const software = group('g-soft', 'filter', [], filter('entity_type', ['Software']));
    const indicators = group('g-ind', 'filter', [], filter('entity_type', ['Indicator']));
    const rule = (id: string, link: { relationship_types: string[]; group_ids: string[] } | null, filters: string | null, types: string[]) => ({
      id, name: id, applies_to_types: types, applies_to_criterion_id: null, filters, link, path_condition: null, points: 10, enabled: true,
    });
    const ir = requirement([systems, software, indicators, threatsGroup], [criterion({ id: 'k', target_types: ['Vulnerability', 'Report'], conditions: [{ id: 'k1', name: 'recent', applies_to_types: ['Vulnerability'], filters: filter('created', ['now-6M'], 'gte'), link: null, path_condition: null }] })], [
      rule('r1', null, filter('x_opencti_cisa_kev', ['true']), ['Vulnerability']),
      rule('r2', null, filter('x_opencti_cvss_base_score', ['9'], 'gte'), ['Vulnerability']),
      rule('r3', { relationship_types: ['has'], group_ids: ['g-soft'] }, null, ['Vulnerability']),
      rule('r4', { relationship_types: ['has'], group_ids: ['g-sys'] }, null, ['Vulnerability']),
      rule('r5', { relationship_types: ['targets', 'exploits', 'uses', 'related-to'], group_ids: ['g-threats'] }, null, ['Vulnerability']),
      rule('r6', { relationship_types: ['object'], group_ids: ['g-ind'] }, null, ['Report']),
      rule('r7', { relationship_types: ['object'], group_ids: ['g-threats'] }, null, ['Report']),
    ]);
    await computeMatchScore(context, user, ir, pseudo(vulnerabilitySample[0], ['k']));
    const ms = await timeEach([...vulnerabilitySample, ...reportSample], (e) => computeMatchScore(context, user, ir, pseudo(e, ['k'])));
    record('5 rescore', 'Full rescore of one entity, PIR-02-like (1 condition, 7 rules)', ms, 'ms per entity');
  }
  // endregion

  // region 6. Second hop and on-demand eligibility
  {
    const ir = requirement([], [
      criterion({ id: 'c-sys', kind: 'graph', from_in_requirement: true, from_types: ['Vulnerability'], relationship_types: ['has'], direction: 'incoming', target_types: ['System'] }),
      criterion({ id: 'c-rep', kind: 'graph', from_in_requirement: true, from_types: ['Vulnerability'], relationship_types: ['object'], direction: 'incoming', target_types: ['Report'] }),
    ]);
    const state = await buildEngineState(context, user, ir);
    let found = 0;
    const ms = await timeEach(vulnerabilitySample, async (e) => {
      found += (await evaluateExistingRelationships(context, user, state, e)).length;
    }, 1);
    record('6 second hop', 'Backfill of an entity that enters (2 second hop criteria)', ms, 'ms per entering entity', `${found} candidates found`);
  }
  {
    const europeRules = requirement([europe], [criterion({ id: 'k', kind: 'graph', from_group_ids: ['g-europe'], relationship_types: ['targets'], direction: 'outgoing', target_types: ['Intrusion-Set', 'Malware', 'Threat-Actor-Group', 'Campaign'] })]);
    const state = await buildEngineState(context, user, europeRules);
    const ms = await timeEach(threatSample, (e) => evaluateCandidate(context, user, state, e, europeRules.ir_scope_criteria));
    record('6 second hop', 'On-demand: re-evaluate a skipped entity on a new fact (1 graph criterion)', ms, 'ms per entity');
  }
  // endregion

  // region 7. Keywords and containers
  {
    const words = ['ransomware', 'healthcare', 'cve-2024', 'lockbit'];
    const start = performance.now();
    for (let i = 0; i < entityEvents.length; i += 1) findKeyword(entityEvents[i].data, words, ['name', 'description', 'content']);
    record('7 keywords', 'Keyword search in the texts of an entity event (in memory)', [(performance.now() - start) / Math.max(1, entityEvents.length)], 'ms per event');
    const kwIr = requirement([{ ...group('g-kw', 'list', []), kind: 'keywords', keywords: words }], [criterion({ id: 'k', kind: 'keywords', from_group_ids: ['g-kw'], target_types: ['Report', 'Indicator', 'Vulnerability', 'Malware'] })]);
    const kwState = await buildEngineState(context, user, kwIr);
    const reportEvents = entityEvents.filter((e) => (e.data?.object_refs ?? []).length > 0).slice(0, 30);
    if (reportEvents.length > 0) {
      const ms = await timeEach(reportEvents, (e) => evaluateEntity(context, user, kwState, e.data), 1);
      record('7 keywords', 'Container event with a keyword criterion (loads its contained objects)', ms, 'ms per container event', `${reportEvents.length} containers`);
    }
  }
  // endregion

  // region 8. Writes (documents created then deleted)
  {
    const irId = `pir-cost-benchmark-${Date.now()}`;
    const target = criterion({ id: 'c-bench', mode: 'auto' });
    const created: string[] = [];
    const entities = [...threatSample, ...vulnerabilitySample].slice(0, 20);
    const createMs = await timeEach(entities, async (e) => {
      const result = await upsertMatch(context, user, irId, e, target, { criterion_id: 'c-bench', kind: 'attribute', at: new Date().toISOString() });
      if (result) created.push(result.match.id);
    }, 1);
    record('8 writes', 'Create an entity of the requirement (match)', createMs, 'ms per write');
    const items: string[] = [];
    const itemMs = await timeEach(entities.slice(0, 10), async (e) => {
      const item = await createItem(context, user, irId, 'entered', `${e.name} entered`, { entityId: e.id, entityType: e.type });
      if (item) items.push(item.id);
    }, 1);
    record('8 writes', 'Create an inbox item', itemMs, 'ms per write');
    const matches = await internalFindByIds<BasicStoreEntityIntelligenceRequirementMatch>(context, user, created) as BasicStoreEntityIntelligenceRequirementMatch[];
    const writer = createMatchWriter();
    matches.forEach((m) => writer.write(m, { match_score: 42 }));
    record('8 writes', `Grouped score writes of a batch (${matches.length} entities in one bulk)`, [await time(() => writer.flush(context))], 'ms per batch');
    for (let i = 0; i < created.length; i += 1) await deleteMatch(context, user, created[i]);
    for (let i = 0; i < items.length; i += 1) await internalDeleteElementById(context, user, items[i], ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM);
  }
  // endregion

  // eslint-disable-next-line no-console
  console.log(`PIR_COST_RESULTS ${JSON.stringify({ at: new Date().toISOString(), events: events.length, results })}`);
};

// Connections, as the platform opens them at startup (scripts do not)
await searchEngineInit();
await redisInit();
cacheManager.init();
initLockFork();
await run();
logApp.info('[SCRIPT] PIR cost benchmark done');
process.exit(0);
