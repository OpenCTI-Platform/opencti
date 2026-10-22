// Lock-free write path, correctness.
// Part 1, parity: the same steps run through today's path (createEntity / createRelation, one by one) and through
// the lock-free path (in chunks, with settlers), in two worlds told apart by a name prefix. The stored documents,
// the meta relationships and the stream events of both worlds must be identical, ids replaced by names.
// Part 2, behaviours parity cannot show: concurrency, out-of-order arrival, restarts, deletes, renames, drafts,
// access, backfill, visibility.
import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { ADMIN_USER, getAuthUser, getUserIdByEmail, testContext, USER_EDITOR, USER_PARTICIPATE } from '../../utils/testQuery';
import { createEntity, createRelation, deleteElementById, storeLoadByIdWithRefs } from '../../../src/database/middleware';
import { fullRelationsList, storeLoadById } from '../../../src/database/middleware-loader';
import { elRawSearch, elRefreshIndices } from '../../../src/database/engine';
import {
  inferIndexFromConceptType,
  READ_DATA_INDICES,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
} from '../../../src/database/utils';
import { fetchStreamEventsRangeFromEventId } from '../../../src/database/stream/stream-handler';
import { generateStandardId, MARKING_TLP_AMBER, MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import { ENTITY_DOMAIN_NAME, ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';
import { addLabel } from '../../../src/domain/label';
import { addKillChainPhase } from '../../../src/domain/killChainPhase';
import { addExternalReference } from '../../../src/domain/externalReference';
import { addDraftWorkspace } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { benchParam, createOne, denormalizedCount, RUN_ID, writeResults } from '../bench-utils';
import { backfillIdentities } from '../../../src/database/lockfree/backfill';
import { deterministicId, identityKeys, lookupKeys, setKeys } from '../../../src/database/lockfree/identity';
import { mgetRaw, toElements } from '../../../src/database/lockfree/load';
import { countPending, processPending } from '../../../src/database/lockfree/pending';
import { PARTITIONS, queueDepth, readTasks } from '../../../src/database/lockfree/queue';
import { deleteEntity, newSettler, registerUser, renameEntity, settleAll, writeEntities, writeRelations } from '../lockfree/run';
import type { EntityItem } from '../../../src/database/lockfree/writer';

const N = benchParam('N', 30);
const SETTLE_MS = benchParam('SETTLE_MS', 100);
const chunked = { chunkSize: 100, concurrency: 4, settleEveryMs: SETTLE_MS };
const single = { chunkSize: 1, concurrency: 8, settleEveryMs: SETTLE_MS };
const range = (n: number) => [...Array(n).keys()];
const refresh = () => elRefreshIndices([...READ_DATA_INDICES, ...READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED]);
const sid = (type: string, name: string) => generateStandardId(type, { name });
const META_TYPES = /^(created-by|object-marking|object-label|external-reference|kill-chain-phase|object|granted-to)$/;

// ---------------------------------------------------------------------------------------------------------------
// Worlds and normalization
// ---------------------------------------------------------------------------------------------------------------
type World = 'tdy' | 'lkf';
const nm = (world: World, label: string) => `bench-${RUN_ID}-${world}-${label}`;
// Values each world needs its own of (MITRE ids, hashes) are registered here and compared as placeholders
const worldValues = new Map<string, string>();
const strip = (value: string) => {
  let out = value.replace(new RegExp(`bench-${RUN_ID}-(tdy|lkf)-`, 'g'), 'W-');
  worldValues.forEach((placeholder, worldValue) => {
    out = out.split(worldValue).join(placeholder);
  });
  return out;
};

const search = async (index: string | string[], query: any, size = 10000) => {
  const response: any = await elRawSearch(testContext, ADMIN_USER, null, { index, size, body: { query } });
  return response.hits.hits.map((h: any) => ({ ...h._source, _index: h._index }));
};
const worldDocs = async (world: World) => {
  await refresh();
  const entities = await search([READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES], {
    bool: { should: [{ wildcard: { 'name.keyword': `*${RUN_ID}-${world}-*` } }, { wildcard: { 'value.keyword': `*${RUN_ID}-${world}-*` } }, { wildcard: { 'x_opencti_additional_names.keyword': `*${RUN_ID}-${world}-*` } }] },
  });
  const entityIds = entities.map((e: any) => e.internal_id);
  const relations = entityIds.length === 0 ? [] : await search(READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, {
    nested: { path: 'connections', query: { terms: { 'connections.internal_id.keyword': entityIds } } },
  });
  return { entities, relations };
};
const SKIPPED = new Set(['internal_id', 'id', 'standard_id', 'x_opencti_stix_ids', 'i_aliases_ids', 'created_at', 'updated_at', 'refreshed_at', 'modified', 'created', '_index', 'i_raw']);
const normalizeValue = (value: any, labels: Map<string, string>): any => {
  if (typeof value === 'string') return labels.get(value) ?? labels.get(value.toLowerCase()) ?? strip(value);
  if (Array.isArray(value)) return value.map((v) => normalizeValue(v, labels)).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().filter((k) => !SKIPPED.has(k)).map((k) => [k, normalizeValue(value[k], labels)]));
  return value;
};
const normalizeDoc = (doc: any, labels: Map<string, string>) => {
  const out: any = {};
  Object.keys(doc).sort().forEach((key) => {
    if (SKIPPED.has(key)) return;
    if (key === 'i_attributes') out[key] = (doc[key] ?? []).map((a: any) => a.name).sort();
    else out[key] = normalizeValue(doc[key], labels);
  });
  return out;
};
const endsOf = (r: any) => ({ from: r.connections.find((c: any) => c.role.endsWith('_from')), to: r.connections.find((c: any) => c.role.endsWith('_to')) });
const buildLabels = (entities: any[], relations: any[]) => {
  const labels = new Map<string, string>();
  const put = (ids: string[], label: string) => ids.filter(Boolean).forEach((id) => {
    labels.set(id, label);
    labels.set(id.toLowerCase(), label);
  });
  entities.forEach((e) => put([e.internal_id, e.standard_id, ...(e.x_opencti_stix_ids ?? [])], `${e.entity_type}:${strip(e.name ?? e.value ?? e.x_opencti_additional_names?.[0] ?? '?')}`));
  relations.filter((r) => !META_TYPES.test(r.entity_type)).forEach((r) => {
    const { from, to } = endsOf(r);
    put([r.internal_id, r.standard_id, ...(r.x_opencti_stix_ids ?? [])], `${r.entity_type}(${labels.get(from.internal_id) ?? strip(from.name ?? '')}->${labels.get(to.internal_id) ?? strip(to.name ?? '')}@${r.start_time ?? r.first_seen ?? ''})`);
  });
  return labels;
};
const snapshot = async (world: World) => {
  const { entities, relations } = await worldDocs(world);
  const labels = buildLabels(entities, relations);
  const docs = new Map<string, any>();
  [...entities, ...relations.filter((r: any) => !META_TYPES.test(r.entity_type))]
    .forEach((d: any) => docs.set(labels.get(d.internal_id) as string, normalizeDoc(d, labels)));
  const metas = relations.filter((r: any) => META_TYPES.test(r.entity_type)).map((r: any) => {
    const { from, to } = endsOf(r);
    return `${r.entity_type}|${labels.get(from.internal_id) ?? strip(from.name ?? '')}|${labels.get(to.internal_id) ?? strip(to.name ?? '')}`;
  }).sort();
  return { docs, metas, labels };
};

// Stream events of a world since a stream id: type, object, and the STIX keys it carries (updates: patch paths)
const worldEvents = async (startId: string, labels: Map<string, string>) => {
  const events: any[] = [];
  await fetchStreamEventsRangeFromEventId(startId, (batch: any[]) => {
    events.push(...batch);
  }, { streamBatchSize: 5000 } as any);
  return events
    .map((e) => ({ type: e.event, label: labels.get(e.data?.data?.id), data: e.data }))
    .filter((e) => e.label)
    .map((e) => `${e.type}|${e.label}|${e.type === 'update' ? (e.data.context?.patch ?? []).map((p: any) => `${p.op}:${p.path.replace(/\/\d+/g, '/#')}`).sort().join(',') : Object.keys(e.data.data).sort().join(',')}`)
    .sort();
};

const diffSnapshots = (a: Awaited<ReturnType<typeof snapshot>>, b: Awaited<ReturnType<typeof snapshot>>) => {
  const problems: any[] = [];
  R.uniq([...a.docs.keys(), ...b.docs.keys()]).sort().forEach((key) => {
    const x = a.docs.get(key);
    const y = b.docs.get(key);
    if (!x || !y) {
      problems.push({ object: key, only_in: x ? 'today' : 'lockfree' });
      return;
    }
    const fields = R.uniq([...Object.keys(x), ...Object.keys(y)]).filter((f) => !R.equals(x[f], y[f]));
    if (fields.length > 0) problems.push({ object: key, fields: Object.fromEntries(fields.map((f) => [f, { today: x[f], lockfree: y[f] }])) });
  });
  const metaDiff = { only_today: R.difference(a.metas, b.metas), only_lockfree: R.difference(b.metas, a.metas) };
  if (metaDiff.only_today.length || metaDiff.only_lockfree.length) problems.push({ meta_relationships: metaDiff });
  return problems;
};

// ---------------------------------------------------------------------------------------------------------------
describe('Lock-free behaviours scenario', () => {
  it('matches today on every behaviour', async () => {
    const results: Record<string, any> = { params: { n: N, settle_every_ms: SETTLE_MS } };
    const failures: string[] = [];
    const check = (label: string, ok: boolean, detail: any = undefined) => {
      results.checks = { ...(results.checks ?? {}), [label]: ok ? 'ok' : { failed: detail ?? true } };
      if (!ok) failures.push(label);
    };
    const editor = await getAuthUser(await getUserIdByEmail(USER_EDITOR.email) as string);
    const participant = await getAuthUser(await getUserIdByEmail(USER_PARTICIPATE.email) as string);
    registerUser(editor);
    registerUser(participant);

    // Shared refs, created by today's path; the lock-free world finds them through the backfill
    const author: any = await createOne(ENTITY_TYPE_IDENTITY_ORGANIZATION, 'lfp-author');
    const labelValues = [0, 1, 2].map((l) => `bench-${RUN_ID}-lfp-label-${l}`);
    for (const value of labelValues) await addLabel(testContext, ADMIN_USER, { value });
    const killChain: any = await addKillChainPhase(testContext, ADMIN_USER, { kill_chain_name: 'mitre-attack', phase_name: `bench-${RUN_ID}-phase`, x_opencti_order: 1 });
    const extRefs: any[] = [];
    for (let e = 0; e < 2; e += 1) extRefs.push(await addExternalReference(testContext, ADMIN_USER, { source_name: `bench-${RUN_ID}-src-${e}`, url: `https://example.com/${RUN_ID}/${e}` }));
    await storeLoadById(testContext, ADMIN_USER, MARKING_TLP_GREEN, ENTITY_TYPE_MARKING_DEFINITION);
    results.backfill = await backfillIdentities();
    check('backfill_ran', results.backfill.entities > 0);

    // =========================================================================================================
    // Part 1: parity with today's path
    // =========================================================================================================
    const refs = { createdBy: author.standard_id, objectMarking: [MARKING_TLP_GREEN], objectLabel: labelValues, externalReferences: [extRefs[0].standard_id] };
    const steps = (w: World): { entities?: EntityItem[]; relations?: Record<string, any>[] }[] => {
      const is = (i: number) => sid(ENTITY_TYPE_INTRUSION_SET, nm(w, `is-${i}`));
      const mw = (i: number) => sid(ENTITY_TYPE_MALWARE, nm(w, `mw-${i}`));
      const mitreId = `T${RUN_ID.slice(-4)}${w === 'tdy' ? 1 : 2}`;
      const ap = generateStandardId(ENTITY_TYPE_ATTACK_PATTERN, { name: nm(w, 'ap'), x_mitre_id: mitreId });
      const hex = (seed: string, length: number) => Buffer.from(`${RUN_ID}-${w}-${seed}`).toString('hex').padEnd(length, '0').slice(0, length);
      const sha = hex('sha', 64);
      const md5 = hex('md5', 32);
      const sha1 = hex('sha1', 40);
      worldValues.set(sha1, '<sha-1>');
      worldValues.set(mitreId, '<mitre-id>');
      worldValues.set(sha, '<sha-256>');
      worldValues.set(md5, '<md5>');
      const domain = `${nm(w, 'domain')}.example`;
      return [
        // 1. Creations with every kind of ref
        { entities: [
          ...range(5).map((i) => ({ type: ENTITY_TYPE_INTRUSION_SET, input: { name: nm(w, `is-${i}`), description: 'first', confidence: 60, aliases: [nm(w, `is-${i}-alias`)], ...refs } })),
          ...range(5).map((i) => ({ type: ENTITY_TYPE_MALWARE, input: { name: nm(w, `mw-${i}`), is_family: true, description: 'first', confidence: 60, ...refs } })),
          { type: ENTITY_TYPE_ATTACK_PATTERN, input: { name: nm(w, 'ap'), x_mitre_id: mitreId, killChainPhases: [killChain.standard_id], ...refs } },
          { type: ENTITY_DOMAIN_NAME, input: { value: domain, ...refs } },
          { type: ENTITY_HASHED_OBSERVABLE_STIX_FILE, input: { hashes: { 'SHA-256': sha }, x_opencti_additional_names: [nm(w, 'file')], ...refs } },
          { type: ENTITY_HASHED_OBSERVABLE_STIX_FILE, input: { hashes: { 'SHA-1': sha1 }, x_opencti_additional_names: [nm(w, 'file-other')], ...refs } },
        ] },
        // 2. Relationships with refs and dates, a sighting
        { relations: [
          ...range(5).map((i) => ({ relationship_type: RELATION_USES, fromId: is(i), toId: mw(i), start_time: '2024-01-01T00:00:00.000Z', stop_time: '2024-02-01T00:00:00.000Z', description: 'first', confidence: 60, ...refs })),
          { relationship_type: RELATION_USES, fromId: mw(0), toId: ap, ...refs },
          { relationship_type: STIX_SIGHTING_RELATIONSHIP, fromId: mw(1), toId: author.standard_id, first_seen: '2024-03-01T00:00:00.000Z', last_seen: '2024-03-02T00:00:00.000Z', attribute_count: 1, ...refs },
        ] },
        // 3. Copies: higher confidence replaces, lower does not, new alias and label, marking upgrade, alias match, hashes
        { entities: [
          { type: ENTITY_TYPE_INTRUSION_SET, input: { name: nm(w, 'is-0'), description: 'second', confidence: 80, ...refs } },
          { type: ENTITY_TYPE_INTRUSION_SET, input: { name: nm(w, 'is-1'), description: 'lower', confidence: 10, ...refs } },
          { type: ENTITY_TYPE_INTRUSION_SET, input: { name: nm(w, 'is-2'), aliases: [nm(w, 'is-2-second-alias')], ...refs, objectLabel: [...labelValues, `bench-${RUN_ID}-lfp-label-new`] } },
          { type: ENTITY_TYPE_INTRUSION_SET, input: { name: nm(w, 'is-3'), ...refs, objectMarking: [MARKING_TLP_AMBER], externalReferences: [extRefs[1].standard_id] } },
          { type: ENTITY_TYPE_INTRUSION_SET, input: { name: nm(w, 'is-4'), description: 'first', confidence: 60, aliases: [nm(w, 'is-4-alias')], ...refs } },
          { type: ENTITY_TYPE_MALWARE, input: { name: nm(w, 'mw-alias-of-0'), aliases: [nm(w, 'mw-0')], is_family: true, ...refs } },
          { type: ENTITY_HASHED_OBSERVABLE_STIX_FILE, input: { hashes: { 'SHA-256': sha, MD5: md5 }, ...refs } },
          // two existing objects matched at once: today upserts the standard id one, without the colliding alias
          { type: ENTITY_TYPE_MALWARE, input: { name: nm(w, 'mw-3'), aliases: [nm(w, 'mw-4')], is_family: true, ...refs } },
        ] },
        // hashes linking two existing files: today merges them
        { entities: [{ type: ENTITY_HASHED_OBSERVABLE_STIX_FILE, input: { hashes: { 'SHA-256': sha, 'SHA-1': sha1 }, ...refs } }] },
        // 4. Relationship copies: inside the window (merge), outside it (new), lower confidence, a second sighting
        { relations: [
          { relationship_type: RELATION_USES, fromId: is(0), toId: mw(0), start_time: '2024-01-10T00:00:00.000Z', stop_time: '2024-02-05T00:00:00.000Z', description: 'second', confidence: 80, ...refs },
          { relationship_type: RELATION_USES, fromId: is(1), toId: mw(1), start_time: '2025-06-01T00:00:00.000Z', stop_time: '2025-07-01T00:00:00.000Z', description: 'other period', ...refs },
          { relationship_type: RELATION_USES, fromId: is(2), toId: mw(2), start_time: '2024-01-01T00:00:00.000Z', stop_time: '2024-02-01T00:00:00.000Z', description: 'lower', confidence: 10, ...refs },
          { relationship_type: STIX_SIGHTING_RELATIONSHIP, fromId: mw(1), toId: author.standard_id, first_seen: '2024-03-05T00:00:00.000Z', last_seen: '2024-03-06T00:00:00.000Z', attribute_count: 3, ...refs },
        ] },
        // 5. A report holding objects of the world, then again with one more
        { entities: [{ type: ENTITY_TYPE_CONTAINER_REPORT, input: { name: nm(w, 'report'), published: '2024-04-01T00:00:00.000Z', objects: [...range(5).map(is), ...range(5).map(mw), ap], ...refs } }] },
        { entities: [{ type: ENTITY_TYPE_CONTAINER_REPORT, input: { name: nm(w, 'report'), published: '2024-04-01T00:00:00.000Z', objects: [...range(5).map(is), ...range(5).map(mw), ap, generateStandardId(ENTITY_DOMAIN_NAME, { value: domain })], ...refs } }] },
      ];
    };
    const runToday = async (w: World) => {
      const errors: string[] = [];
      for (const step of steps(w)) {
        for (const e of step.entities ?? []) await createEntity(testContext, ADMIN_USER, e.input, e.type).catch((err: any) => errors.push(`${e.type}:${err.message}`));
        for (const r of step.relations ?? []) await createRelation(testContext, ADMIN_USER, r).catch((err: any) => errors.push(`${r.relationship_type}:${err.message}`));
      }
      return errors;
    };
    const runLockFree = async (w: World) => {
      const errors: any[] = [];
      for (const step of steps(w)) {
        if (step.entities) errors.push(...Object.entries((await writeEntities(step.entities, chunked)).errors));
        if (step.relations) {
          const written = await writeRelations(step.relations, chunked);
          errors.push(...Object.entries(written.errors), ...range(written.statuses.pending ?? 0).map(() => 'pending (today: missing reference)'));
        }
      }
      return errors;
    };
    const streamStartToday = `${Date.now()}-0`;
    results.parity_today_errors = await runToday('tdy');
    const streamStartLockFree = `${Date.now()}-0`;
    results.parity_lockfree_errors = await runLockFree('lkf');
    const today = await snapshot('tdy');
    const lockfree = await snapshot('lkf');
    const parity = diffSnapshots(today, lockfree);
    results.parity_objects = today.docs.size;
    results.parity_meta_relationships = today.metas.length;
    check('parity_same_errors', results.parity_today_errors.length === results.parity_lockfree_errors.length, { today: results.parity_today_errors, lockfree: results.parity_lockfree_errors });
    check('parity_stored_documents', parity.length === 0, parity.slice(0, 12));
    const todayEvents = await worldEvents(streamStartToday, today.labels);
    const lockfreeEvents = await worldEvents(streamStartLockFree, lockfree.labels);
    const eventDiff = { only_today: R.difference(todayEvents, lockfreeEvents), only_lockfree: R.difference(lockfreeEvents, todayEvents) };
    results.parity_events = { today: todayEvents.length, lockfree: lockfreeEvents.length };
    check('parity_stream_events', eventDiff.only_today.length === 0 && eventDiff.only_lockfree.length === 0, { only_today: eventDiff.only_today.slice(0, 10), only_lockfree: eventDiff.only_lockfree.slice(0, 10) });

    // =========================================================================================================
    // Part 2: behaviours
    // =========================================================================================================
    const ent = (type: string, name: string, extra: Record<string, any> = {}): EntityItem => ({ type, input: { name, description: 'benchmark', ...extra } });
    const uses = (from: string, to: string, extra: Record<string, any> = {}) => ({ relationship_type: RELATION_USES, fromId: from, toId: to, ...extra });
    const sources = range(N).map((i) => ent(ENTITY_TYPE_INTRUSION_SET, `bench-${RUN_ID}-b-src-${i}`));
    await writeEntities(sources, chunked);
    const srcStd = (i: number) => sid(ENTITY_TYPE_INTRUSION_SET, sources[i].input.name);
    const idOf = (type: string, name: string) => deterministicId(sid(type, name).toLowerCase());
    const relationsTouching = async (id: string, type?: string) => {
      await refresh();
      const filter: any[] = [{ nested: { path: 'connections', query: { term: { 'connections.internal_id.keyword': id } } } }];
      if (type) filter.push({ term: { 'entity_type.keyword': type } });
      return search(READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, { bool: { filter } });
    };
    const named = async (names: string[]) => {
      await refresh();
      return search(READ_INDEX_STIX_DOMAIN_OBJECTS, { terms: { 'name.keyword': names } });
    };
    const hubIndex = inferIndexFromConceptType(ENTITY_TYPE_MALWARE);
    const malware = (name: string, extra: Record<string, any> = {}) => ent(ENTITY_TYPE_MALWARE, name, { is_family: true, ...extra });

    // Concurrency: the same relationship / entity sent twice at the same moment is stored once
    const dupHub = `bench-${RUN_ID}-b-dup-hub`;
    await writeEntities([malware(dupHub)], chunked);
    const dupInputs = range(N).map((i) => uses(srcStd(i), sid(ENTITY_TYPE_MALWARE, dupHub)));
    results.duplicates = await writeRelations(dupInputs.flatMap((d) => [d, d]), single);
    check('duplicate_relationships_stored_once', (await relationsTouching(idOf(ENTITY_TYPE_MALWARE, dupHub), RELATION_USES)).length === N);
    check('duplicate_relationships_listed_once', (await denormalizedCount(idOf(ENTITY_TYPE_MALWARE, dupHub), hubIndex, RELATION_USES)) === N);
    const dupEntities = range(N).map((i) => malware(`bench-${RUN_ID}-b-dup-entity-${i}`));
    await writeEntities(dupEntities.flatMap((e) => [e, e]), single);
    check('duplicate_entities_stored_once', (await named(dupEntities.map((e) => e.input.name))).length === N);

    // Alias race: "C" and "D" (alias "C") at the same moment never show two objects, even before settling
    const raceC = range(N).map((i) => malware(`bench-${RUN_ID}-b-race-c-${i}`));
    const raceD = range(N).map((i) => malware(`bench-${RUN_ID}-b-race-d-${i}`, { aliases: [`bench-${RUN_ID}-b-race-c-${i}`] }));
    results.alias_race = await writeEntities(range(N).flatMap((i) => [raceC[i], raceD[i]]), { ...single, noSettle: true });
    const raceVisible = (await named([...raceC, ...raceD].map((e) => e.input.name))).length;
    check('alias_race_no_visible_duplicate', raceVisible === N, { found: raceVisible, writer: results.alias_race.writer });
    await settleAll([newSettler()]);

    // Out of order: relationships before their ends wait invisibly, then are written when the ends arrive
    const lateHub = `bench-${RUN_ID}-b-late-hub`;
    const lateSources = range(N).map((i) => ent(ENTITY_TYPE_INTRUSION_SET, `bench-${RUN_ID}-b-late-${i}`));
    results.out_of_order = await writeRelations(lateSources.map((s) => uses(sid(s.type, s.input.name), sid(ENTITY_TYPE_MALWARE, lateHub), refs)), chunked);
    check('out_of_order_waits_invisibly', results.out_of_order.statuses.pending === N && (await relationsTouching(idOf(ENTITY_TYPE_MALWARE, lateHub))).length === 0, results.out_of_order.statuses);
    await writeEntities([malware(lateHub), ...lateSources], chunked);
    await settleAll([newSettler()]);
    const lateRels = await relationsTouching(idOf(ENTITY_TYPE_MALWARE, lateHub), RELATION_USES);
    check('out_of_order_written_when_ends_arrive', lateRels.length === N && (await denormalizedCount(idOf(ENTITY_TYPE_MALWARE, lateHub), hubIndex, RELATION_USES)) === N, { rels: lateRels.length, pending: await countPending() });
    const lateLoaded: any = await storeLoadByIdWithRefs(testContext, ADMIN_USER, lateRels[0]?.internal_id);
    check('out_of_order_complete_with_refs', lateLoaded?.createdBy?.internal_id === author.internal_id && lateLoaded?.objectLabel?.length === 3);
    await writeRelations([uses(srcStd(0), `malware--${uuidv4()}`)], { ...chunked, noSettle: true });
    const expiry = await processPending(async () => undefined, { ttlMs: 0 });
    check('pending_expires', expiry.expired >= 1, expiry);

    // Deletes: references to a deleted entity are refused; relationships the delete missed are removed
    const doomed = `bench-${RUN_ID}-b-doomed`;
    await writeEntities([malware(doomed)], chunked);
    await writeRelations(range(N).map((i) => uses(srcStd(i), sid(ENTITY_TYPE_MALWARE, doomed))), { ...chunked, noSettle: true });
    const doomedId = idOf(ENTITY_TYPE_MALWARE, doomed);
    const [doomedDoc] = await toElements([(await mgetRaw([{ id: doomedId, index: hubIndex }])).get(doomedId) as any]);
    await setKeys([...identityKeys(ENTITY_TYPE_MALWARE, { ...doomedDoc, stix_id: doomedDoc.standard_id }), doomedId].map((key) => ({
      key, owner: { owner_id: doomedId, owner_index: hubIndex, owner_type: ENTITY_TYPE_MALWARE, owner_standard_id: doomedDoc.standard_id }, state: 'deleted' as const,
    })));
    await deleteElementById(testContext, ADMIN_USER, doomedId, ENTITY_TYPE_MALWARE); // no refresh first: the race the settler covers
    await settleAll([newSettler()]);
    check('delete_removes_unseen_relationships', (await relationsTouching(doomedId, RELATION_USES)).length === 0);
    const afterDelete = await writeRelations([uses(srcStd(0), sid(ENTITY_TYPE_MALWARE, doomed))], chunked);
    check('delete_refuses_new_references', afterDelete.statuses.error === 1, afterDelete.statuses);
    const gone = `bench-${RUN_ID}-b-gone`;
    await writeEntities([malware(gone)], chunked);
    await deleteEntity({ internal_id: idOf(ENTITY_TYPE_MALWARE, gone), _index: hubIndex });
    const recreated = await writeEntities([malware(gone)], chunked);
    check('recreate_after_delete', recreated.statuses.created === 1 && (await named([gone])).length === 1, recreated.statuses);
    // A relationship deleted by today's path (from the interface): written again, it is created again, as today
    const relGoneHub = `bench-${RUN_ID}-b-rel-gone-hub`;
    await writeEntities([malware(relGoneHub)], chunked);
    await writeRelations([uses(srcStd(0), sid(ENTITY_TYPE_MALWARE, relGoneHub))], chunked);
    const [relGone] = await relationsTouching(idOf(ENTITY_TYPE_MALWARE, relGoneHub), RELATION_USES);
    await deleteElementById(testContext, ADMIN_USER, relGone.internal_id, RELATION_USES);
    const relAgain = await writeRelations([uses(srcStd(0), sid(ENTITY_TYPE_MALWARE, relGoneHub))], chunked);
    const relAgainStored = await relationsTouching(idOf(ENTITY_TYPE_MALWARE, relGoneHub), RELATION_USES);
    check('relationship_recreated_after_delete', relAgain.statuses.created === 1 && relAgainStored.length === 1, relAgain.statuses);

    // Rename through the platform: references by the new and by the old name resolve as they do today
    const renameCase = async (world: 'today' | 'lockfree') => {
      const before = `bench-${RUN_ID}-b-${world}-before-rename`;
      const after = `bench-${RUN_ID}-b-${world}-after-rename`;
      let entityId: string;
      if (world === 'today') entityId = (await createEntity(testContext, ADMIN_USER, { name: before, is_family: true }, ENTITY_TYPE_MALWARE) as any).internal_id;
      else {
        await writeEntities([malware(before)], chunked);
        entityId = idOf(ENTITY_TYPE_MALWARE, before);
      }
      await renameEntity({ internal_id: entityId, _index: hubIndex, entity_type: ENTITY_TYPE_MALWARE }, after);
      const refsByName = [uses(srcStd(0), sid(ENTITY_TYPE_MALWARE, after)), uses(srcStd(1), sid(ENTITY_TYPE_MALWARE, before))];
      if (world === 'today') {
        const outcomes = await Promise.all(refsByName.map((r) => createRelation(testContext, ADMIN_USER, r).then(() => 'created', () => 'refused')));
        return outcomes.join(',');
      }
      const written = await writeRelations(refsByName, chunked);
      return written.results.map((r: any) => (r.status === 'created' ? 'created' : 'refused')).join(',');
    };
    const renameToday = await renameCase('today');
    const renameLockFree = await renameCase('lockfree');
    check('rename_references_as_today', renameToday === renameLockFree, { today: renameToday, lockfree: renameLockFree });

    // Access, as today: a marking the user does not have is refused; confidence is capped to the user's
    const deniedToday = await createEntity(testContext, editor, { name: `bench-${RUN_ID}-b-red-today`, is_family: true, objectMarking: [MARKING_TLP_RED] }, ENTITY_TYPE_MALWARE)
      .then(() => 'created', (e: any) => e.message);
    const deniedLockFree = await writeEntities([malware(`bench-${RUN_ID}-b-red-lockfree`, { objectMarking: [MARKING_TLP_RED] })], { ...chunked, user: editor });
    check('access_missing_marking_refused', deniedToday !== 'created' && deniedLockFree.statuses.error === 1, { today: deniedToday, lockfree: deniedLockFree.errors });
    await createEntity(testContext, participant, { name: `bench-${RUN_ID}-b-capped-today`, is_family: true, confidence: 90 }, ENTITY_TYPE_MALWARE);
    await writeEntities([malware(`bench-${RUN_ID}-b-capped`, { confidence: 90 })], { ...chunked, user: participant });
    const cappedToday = (await named([`bench-${RUN_ID}-b-capped-today`]))[0];
    const capped = (await named([`bench-${RUN_ID}-b-capped`]))[0];
    check('access_confidence_as_today', capped?.confidence === cappedToday?.confidence, { lockfree: capped?.confidence, today: cappedToday?.confidence });

    // Durable queue: a settler that stops leaves its work to the next one
    const crashHub = `bench-${RUN_ID}-b-crash-hub`;
    await writeEntities([malware(crashHub)], chunked);
    await writeRelations(range(N).map((i) => uses(srcStd(i), sid(ENTITY_TYPE_MALWARE, crashHub))), { ...chunked, noSettle: true });
    await readTasks([...Array(PARTITIONS).keys()], `crashed-${RUN_ID}`, 100000, 1000000); // reads, never acknowledges
    check('restart_work_survives', (await queueDepth()) > 0);
    await settleAll([newSettler({ claimIdleMs: 0 })]);
    const crashListed = await denormalizedCount(idOf(ENTITY_TYPE_MALWARE, crashHub), hubIndex, RELATION_USES);
    check('restart_other_settler_finishes', crashListed === N && (await queueDepth()) === 0, { listed: crashListed, queue: await queueDepth() });

    // Several settlers, one partition each, at the same time
    const multiHub = `bench-${RUN_ID}-b-multi-hub`;
    await writeEntities([malware(multiHub)], chunked);
    const partitioned = [...Array(PARTITIONS).keys()].map((p) => newSettler({ partitions: [p] }));
    await writeRelations(range(N).map((i) => uses(srcStd(i), sid(ENTITY_TYPE_MALWARE, multiHub))), { ...single, settlers: partitioned });
    check('partitioned_settlers', (await denormalizedCount(idOf(ENTITY_TYPE_MALWARE, multiHub), hubIndex, RELATION_USES)) === N);

    // Visibility: with waitForSearch, a write is searchable when the call returns, as today
    const visible = `bench-${RUN_ID}-b-visible`;
    await writeEntities([malware(visible)], { ...chunked, waitForSearch: true, noSettle: true });
    check('wait_for_search_visible_without_refresh', (await search(READ_INDEX_STIX_DOMAIN_OBJECTS, { term: { 'name.keyword': visible } })).length === 1);

    // Drafts: writes in a draft go through today's path, into the draft
    const draft: any = await addDraftWorkspace(testContext, ADMIN_USER, { name: `bench-${RUN_ID}-draft` } as any);
    const drafted = await writeEntities([malware(`bench-${RUN_ID}-b-drafted`)], { ...chunked, context: { ...testContext, draft_context: draft.id } as any });
    check('draft_writes_use_todays_path', drafted.statuses.fallback === 1 && (await named([`bench-${RUN_ID}-b-drafted`])).length === 0, drafted.statuses);

    // Backfill: entities created by today's path are found by the lock-free path once backfilled
    const old = await createOne(ENTITY_TYPE_MALWARE, 'b-old', { is_family: true });
    await backfillIdentities();
    const toOld = await writeRelations([uses(srcStd(0), old.standard_id)], chunked);
    check('backfill_resolves_existing_data', toOld.statuses.created === 1, toOld.statuses);
    // A key left pointing to an object that no longer exists (a wiped platform, a delete without tombstone): the
    // backfill gives it to the object that has it now
    const stale = await createOne(ENTITY_TYPE_MALWARE, 'b-stale', { is_family: true });
    const vanished = { owner_id: uuidv4(), owner_index: hubIndex, owner_type: ENTITY_TYPE_MALWARE, owner_standard_id: stale.standard_id };
    await setKeys([{ key: stale.standard_id.toLowerCase(), owner: vanished }]);
    const staleBackfill = await backfillIdentities();
    const toStale = await writeRelations([uses(srcStd(1), stale.standard_id)], chunked);
    check('backfill_takes_over_stale_keys', staleBackfill.stale_taken_over >= 1 && toStale.statuses.created === 1, { backfill: staleBackfill, statuses: toStale.statuses });

    // Platform reads: lock-free relationships are listed by the platform
    const listed = await fullRelationsList(testContext, ADMIN_USER, RELATION_USES, { toId: idOf(ENTITY_TYPE_MALWARE, lateHub) } as any);
    check('platform_lists_relationships', listed.length === N);
    check('alias_keys_resolve', (await lookupKeys([sid(ENTITY_TYPE_MALWARE, raceD[0].input.name).toLowerCase()])).size === 1);

    results.failures = failures;
    writeResults('lockfree-behaviours', results);
    expect(failures).toEqual([]);
  });
});
