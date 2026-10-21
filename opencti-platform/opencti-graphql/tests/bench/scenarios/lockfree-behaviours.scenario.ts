// Lock-free prototype, correctness: every behaviour today's path guarantees with locks and searches, exercised
// on the prototype and checked on the stored documents and through the platform's own loaders.
// Each case writes its result and a list of failed checks; the test fails if any check fails.
import { describe, expect, it } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { createEntity, createRelation, deleteElementById, storeLoadByIdWithRefs } from '../../../src/database/middleware';
import { fullRelationsList, storeLoadById } from '../../../src/database/middleware-loader';
import { elRawSearch, elRefreshIndices } from '../../../src/database/engine';
import { inferIndexFromConceptType, READ_DATA_INDICES, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../../src/database/utils';
import { MARKING_TLP_AMBER, MARKING_TLP_GREEN, generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { RELATION_INDICATES, RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { addLabel } from '../../../src/domain/label';
import { addIndicator } from '../../../src/modules/indicator/indicator-domain';
import { benchParam, createOne, denormalizedCount, pool, RUN_ID, writeResults } from '../bench-utils';
import { deterministicId, identityKeys, lookupKeys, registerExisting, setKeys } from '../lockfree/identity';
import { fetchDocs, relationKey } from '../lockfree/store';
import { Settler } from '../lockfree/settler';
import { deleteEntity, renameEntity, settleAll, writeEntities, writeRelations } from '../lockfree/run';
import type { EntityInput, RelationInput } from '../lockfree/writer';

const N = benchParam('N', 50);
const CONCURRENCY = benchParam('CONCURRENCY', 8);
const SETTLE_MS = benchParam('SETTLE_MS', 100);
const single = { chunkSize: 1, concurrency: CONCURRENCY, settleEveryMs: SETTLE_MS };
const chunked = { chunkSize: 100, concurrency: 1, settleEveryMs: SETTLE_MS };

const name = (label: string, i?: number) => `bench-${RUN_ID}-lf-${label}${i === undefined ? '' : `-${i}`}`;
const sid = (type: string, entityName: string) => generateStandardId(type, { name: entityName });
const idOf = (type: string, entityName: string) => deterministicId(sid(type, entityName));
const range = (n: number) => [...Array(n).keys()];
const refresh = () => elRefreshIndices([...READ_DATA_INDICES, ...READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED]);

// Relationships touching an id, by search (after a refresh): what the platform's reads see
const relationsTouching = async (id: string, type?: string) => {
  await refresh();
  const filter: any[] = [{ nested: { path: 'connections', query: { term: { 'connections.internal_id.keyword': id } } } }];
  if (type) filter.push({ term: { 'entity_type.keyword': type } });
  const query = { index: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, size: 10000, body: { query: { bool: { filter } } } };
  const response: any = await elRawSearch(testContext, ADMIN_USER, null, query);
  return response.hits.hits.map((h: any) => h._source);
};
const loadDoc = async (index: string, id: string) => (await fetchDocs([{ index, id }])).get(id);
const entitiesNamed = async (names: string[]) => {
  await refresh();
  const response: any = await elRawSearch(testContext, ADMIN_USER, null, { index: READ_INDEX_STIX_DOMAIN_OBJECTS, size: 10000, body: { query: { terms: { 'name.keyword': names } } } });
  return response.hits.hits.map((h: any) => h._source);
};
const uses = (from: string, to: string, extra: Partial<RelationInput> = {}): RelationInput => ({
  relationship_type: RELATION_USES, source_ref: from, target_ref: to, source_type: ENTITY_TYPE_INTRUSION_SET, target_type: ENTITY_TYPE_MALWARE, ...extra,
});
const entity = (type: string, entityName: string, extra: Partial<EntityInput> = {}): EntityInput => ({ type, name: entityName, description: 'benchmark', ...extra });
// Ids, timestamps and names change between two objects; everything else must match
const shape = (doc: any) => Object.keys(doc).filter((k) => !/(_at$|^created$|^modified$|^internal_id$|^standard_id$|^id$|^name$|^i_aliases_ids$|^x_opencti_stix_ids$|^creator_id$|^_|^i_source_keys$)/.test(k)).sort();

describe('Lock-free behaviours scenario', () => {
  it('checks every behaviour of the lock-free prototype', async () => {
    const results: Record<string, any> = { params: { n: N, concurrency: CONCURRENCY, settle_every_ms: SETTLE_MS } };
    const failures: string[] = [];
    const check = (label: string, ok: boolean, detail: any = undefined) => {
      results.checks = { ...(results.checks ?? {}), [label]: ok ? 'ok' : { failed: detail ?? true } };
      if (!ok) failures.push(label);
    };

    // Shared refs, registered once in the identity index (the backfill a migration would do)
    const author: any = await createOne(ENTITY_TYPE_IDENTITY_ORGANIZATION, 'lf-author');
    const labels: any[] = [];
    for (let l = 0; l < 3; l += 1) labels.push(await addLabel(testContext, ADMIN_USER, { value: `bench-${RUN_ID}-lf-label-${l}` }));
    const green: any = await storeLoadById(testContext, ADMIN_USER, MARKING_TLP_GREEN, ENTITY_TYPE_MARKING_DEFINITION);
    const amber: any = await storeLoadById(testContext, ADMIN_USER, MARKING_TLP_AMBER, ENTITY_TYPE_MARKING_DEFINITION);
    await registerExisting([author, ...labels, green, amber]);
    const refs = { createdBy: author.standard_id, objectMarking: [MARKING_TLP_GREEN], objectLabel: labels.map((l) => l.standard_id) };

    // 1. Entities with refs: created with derived ids, refs stored as today (meta relationships + rel_* fields)
    const sources = range(N).map((i) => entity(ENTITY_TYPE_INTRUSION_SET, name('src', i), refs));
    results.entities_with_refs = await writeEntities(sources, chunked);
    const loadedEntity: any = await storeLoadByIdWithRefs(testContext, ADMIN_USER, idOf(ENTITY_TYPE_INTRUSION_SET, name('src', 0)));
    check('entity_created_with_derived_id', loadedEntity?.internal_id === idOf(ENTITY_TYPE_INTRUSION_SET, name('src', 0)));
    check('entity_refs_loaded_by_platform', loadedEntity?.createdBy?.internal_id === author.internal_id
    && loadedEntity?.objectMarking?.map((m: any) => m.internal_id).join() === green.internal_id
    && loadedEntity?.objectLabel?.length === 3, { markings: loadedEntity?.objectMarking?.length, labels: loadedEntity?.objectLabel?.length });
    check('entity_meta_relationships', (await relationsTouching(loadedEntity.internal_id)).length === 5);

    // 2. Parity with today's path: the same entity and relationship written both ways have the same stored fields
    const todayEntity: any = await createEntity(testContext, ADMIN_USER, { name: name('parity-today'), description: 'benchmark', createdBy: author.internal_id, objectMarking: [green.internal_id], objectLabel: labels.map((l) => l.internal_id) }, ENTITY_TYPE_INTRUSION_SET);
    const target: any = await createOne(ENTITY_TYPE_MALWARE, 'lf-parity-target');
    await registerExisting([todayEntity, target]);
    await createRelation(testContext, ADMIN_USER, { fromId: todayEntity.internal_id, toId: target.internal_id, relationship_type: RELATION_USES, description: 'benchmark', createdBy: author.internal_id, objectMarking: [green.internal_id], objectLabel: labels.map((l) => l.internal_id) });
    await writeRelations([uses(sid(ENTITY_TYPE_INTRUSION_SET, name('src', 0)), target.standard_id, { description: 'benchmark', ...refs })], chunked);
    const todayEntityDoc = await loadDoc(todayEntity._index, todayEntity.internal_id);
    const lfEntityDoc = await loadDoc(loadedEntity._index, loadedEntity.internal_id);
    check('parity_entity_fields', JSON.stringify(shape(todayEntityDoc)) === JSON.stringify(shape(lfEntityDoc)), { today: shape(todayEntityDoc), lockfree: shape(lfEntityDoc) });
    const parityRels = (await relationsTouching(target.internal_id, RELATION_USES));
    const todayRel = parityRels.find((r: any) => r.connections.some((c: any) => c.internal_id === todayEntity.internal_id));
    const lfRel = parityRels.find((r: any) => r.connections.some((c: any) => c.internal_id === loadedEntity.internal_id));
    check('parity_relationship_fields', !!todayRel && !!lfRel && JSON.stringify(shape(todayRel)) === JSON.stringify(shape(lfRel)), { today: todayRel && shape(todayRel), lockfree: lfRel && shape(lfRel) });
    check('parity_relationship_meta', (await relationsTouching(todayRel.internal_id)).length === (await relationsTouching(lfRel.internal_id)).length);
    check('parity_target_lists_both', (await denormalizedCount(target.internal_id, target._index, RELATION_USES)) === 2);

    // 3. Interop: today's path sends the same relationship again and finds the lock-free one (no duplicate)
    await createRelation(testContext, ADMIN_USER, { fromId: loadedEntity.internal_id, toId: target.internal_id, relationship_type: RELATION_USES, description: 'from today' });
    check('interop_today_upserts_lockfree_doc', (await relationsTouching(target.internal_id, RELATION_USES)).length === 2);

    // 4. Read path: the platform loads a lock-free relationship with its ends and refs, and lists them
    const lfRelLoaded: any = await storeLoadByIdWithRefs(testContext, ADMIN_USER, lfRel.internal_id);
    check('read_relationship_with_refs', lfRelLoaded?.from?.internal_id === loadedEntity.internal_id && lfRelLoaded?.to?.internal_id === target.internal_id
    && lfRelLoaded?.createdBy?.internal_id === author.internal_id && lfRelLoaded?.objectLabel?.length === 3);

    // 5. Hub, one relationship per call, 8 at a time, and several settlers at once (as several platform nodes)
    const hub = entity(ENTITY_TYPE_MALWARE, name('hub'));
    const hubMulti = entity(ENTITY_TYPE_MALWARE, name('hub-multi'));
    await writeEntities([hub, hubMulti], chunked);
    const hubId = idOf(ENTITY_TYPE_MALWARE, hub.name);
    const hubMultiId = idOf(ENTITY_TYPE_MALWARE, hubMulti.name);
    results.hub_single = await writeRelations(sources.map((s) => uses(sid(s.type, s.name), sid(hub.type, hub.name), refs)), single);
    check('hub_lists_every_source', (await denormalizedCount(hubId, inferIndexFromConceptType(ENTITY_TYPE_MALWARE), RELATION_USES)) === N);
    check('hub_relationship_count', (await relationsTouching(hubId, RELATION_USES)).length === N);
    const hubRelations = await fullRelationsList(testContext, ADMIN_USER, RELATION_USES, { toId: hubId } as any);
    check('platform_lists_hub_relationships', hubRelations.length === N);
    results.multi_settlers = await writeRelations(sources.map((s) => uses(sid(s.type, s.name), sid(hubMulti.type, hubMulti.name))), { ...single, settlers: 4 });
    check('multi_settlers_hub_list', (await denormalizedCount(hubMultiId, inferIndexFromConceptType(ENTITY_TYPE_MALWARE), RELATION_USES)) === N);
    const srcDoc = await loadDoc(inferIndexFromConceptType(ENTITY_TYPE_INTRUSION_SET), idOf(ENTITY_TYPE_INTRUSION_SET, name('src', 1)));
    check('source_lists_both_hubs', (srcDoc['rel_uses.internal_id'] ?? []).filter((id: string) => [hubId, hubMultiId].includes(id)).length === 2);

    // 6. The same relationship sent twice at the same moment by different writers: one document
    const dupHub = entity(ENTITY_TYPE_MALWARE, name('dup-hub'));
    await writeEntities([dupHub], chunked);
    const dupId = idOf(ENTITY_TYPE_MALWARE, dupHub.name);
    const dupInputs = sources.map((s) => uses(sid(s.type, s.name), sid(dupHub.type, dupHub.name)));
    results.duplicates_concurrent = await writeRelations(dupInputs.flatMap((d) => [d, d]), single);
    check('duplicates_one_document_each', (await relationsTouching(dupId, RELATION_USES)).length === N);
    check('duplicates_listed_once', (await denormalizedCount(dupId, inferIndexFromConceptType(ENTITY_TYPE_MALWARE), RELATION_USES)) === N);

    // 7. The same entity sent twice at the same moment: one document
    const dupEntities = range(N).map((i) => entity(ENTITY_TYPE_MALWARE, name('dup-entity', i)));
    results.entity_duplicates_concurrent = await writeEntities(dupEntities.flatMap((e) => [e, e]), single);
    check('entity_duplicates_one_each', (await entitiesNamed(dupEntities.map((e) => e.name))).length === N);

    // 8. Alias match, sequential: "B" with alias "A" lands on the existing "A"
    const aliasA = range(N).map((i) => entity(ENTITY_TYPE_MALWARE, name('alias-a', i)));
    const aliasB = range(N).map((i) => entity(ENTITY_TYPE_MALWARE, name('alias-b', i), { aliases: [name('alias-a', i)] }));
    await writeEntities(aliasA, chunked);
    results.alias_match_sequential = await writeEntities(aliasB, chunked);
    const aliasDocs = await entitiesNamed([...aliasA, ...aliasB].map((e) => e.name));
    check('alias_match_one_entity_each', aliasDocs.length === N && aliasDocs.every((d: any) => (d.aliases ?? []).some((a: string) => a.includes('alias-b'))), { found: aliasDocs.length });
    const aliasOwners = await lookupKeys([sid(ENTITY_TYPE_MALWARE, name('alias-b', 0))]);
    check('alias_keys_point_to_owner', aliasOwners.get(sid(ENTITY_TYPE_MALWARE, name('alias-b', 0)))?.owner_id === idOf(ENTITY_TYPE_MALWARE, name('alias-a', 0)));

    // 9. Alias race: "C" and "D" (alias "C") written at the same moment, and relationships sent to "D" before the
    // settler runs. After settling: one entity per pair, relationships re-pointed, lists fixed on both sides.
    const raceSettler = new Settler();
    const raceC = range(N).map((i) => entity(ENTITY_TYPE_MALWARE, name('race-c', i)));
    const raceD = range(N).map((i) => entity(ENTITY_TYPE_MALWARE, name('race-d', i), { aliases: [name('race-c', i)] }));
    results.alias_race_write = await writeEntities(range(N).flatMap((i) => [raceC[i], raceD[i]]), { ...single, settler: raceSettler, noSettle: true });
    const toDuplicates = range(N).map((i) => uses(sid(sources[i].type, sources[i].name), sid(ENTITY_TYPE_MALWARE, raceD[i].name)));
    results.alias_race_relations = await writeRelations(toDuplicates, { ...chunked, settler: raceSettler, noSettle: true });
    await settleAll([raceSettler]);
    results.alias_race_settler = raceSettler.counters;
    const raceDocs = await entitiesNamed([...raceC, ...raceD].map((e) => e.name));
    check('alias_race_one_entity_each', raceDocs.length === N, { found: raceDocs.length, reconciled: raceSettler.counters.entities_reconciled });
    const raceProblems: any[] = [];
    await pool(range(N), 8, async (i) => {
      const owner = (await lookupKeys([sid(ENTITY_TYPE_MALWARE, raceD[i].name)])).get(sid(ENTITY_TYPE_MALWARE, raceD[i].name));
      const rels = await relationsTouching(owner?.owner_id as string, RELATION_USES);
      const sourceId = idOf(ENTITY_TYPE_INTRUSION_SET, sources[i].name);
      const listed = await denormalizedCount(owner?.owner_id as string, inferIndexFromConceptType(ENTITY_TYPE_MALWARE), RELATION_USES);
      const src = await loadDoc(inferIndexFromConceptType(ENTITY_TYPE_INTRUSION_SET), sourceId);
      const srcList: string[] = src['rel_uses.internal_id'] ?? [];
      const srcHasOwner = srcList.includes(owner?.owner_id as string);
      if (rels.length !== 1 || listed !== 1 || !srcHasOwner) raceProblems.push({ i, rels: rels.length, listed, srcHasOwner });
    });
    check('alias_race_relations_repointed', raceProblems.length === 0, raceProblems.slice(0, 5));

    // 10. Reference by another STIX id: an entity sent with its own STIX id is found by it
    const foreign = range(N).map((i) => entity(ENTITY_TYPE_MALWARE, name('foreign', i), { stix_id: `malware--${uuidv4()}` }));
    await writeEntities(foreign, chunked);
    results.foreign_stix_refs = await writeRelations(foreign.map((f, i) => uses(sid(sources[i].type, sources[i].name), f.stix_id as string)), chunked);
    check('foreign_stix_id_resolved_directly', results.foreign_stix_refs.settler.relations_repointed === undefined
    && (await relationsTouching(idOf(ENTITY_TYPE_MALWARE, foreign[0].name), RELATION_USES)).length === 1);

    // 11. Out of order, by standard id: relationships first, then their ends
    const lateSettler = new Settler();
    const lateHub = entity(ENTITY_TYPE_MALWARE, name('late-hub'));
    const lateSources = range(N).map((i) => entity(ENTITY_TYPE_INTRUSION_SET, name('late-src', i)));
    const toLateHub = lateSources.map((s) => uses(sid(s.type, s.name), sid(lateHub.type, lateHub.name), refs));
    results.out_of_order_relations = await writeRelations(toLateHub, { ...chunked, settler: lateSettler });
    check('out_of_order_waits', lateSettler.pending > 0);
    results.out_of_order_entities = await writeEntities([lateHub, ...lateSources], { ...chunked, settler: lateSettler });
    const lateHubId = idOf(ENTITY_TYPE_MALWARE, lateHub.name);
    const lateRels = await relationsTouching(lateHubId, RELATION_USES);
    check('out_of_order_settled', lateRels.length === N && lateSettler.pending === 0
    && (await denormalizedCount(lateHubId, inferIndexFromConceptType(ENTITY_TYPE_MALWARE), RELATION_USES)) === N, { rels: lateRels.length, pending: lateSettler.pending });
    check('out_of_order_names_filled', lateRels.every((r: any) => r.connections.every((c: any) => c.name)));
    const lateLoaded: any = await storeLoadByIdWithRefs(testContext, ADMIN_USER, lateRels[0].internal_id);
    check('out_of_order_readable', lateLoaded?.from?.name?.includes('late-src') && lateLoaded?.to?.internal_id === lateHubId);

    // 12. Out of order, by a STIX id that is not the standard id: relationships re-pointed when the end arrives
    const strayStix = `malware--${uuidv4()}`;
    const straySettler = new Settler();
    results.stray_relations = await writeRelations(sources.map((s) => uses(sid(s.type, s.name), strayStix)), { ...chunked, settler: straySettler });
    results.stray_entity = await writeEntities([entity(ENTITY_TYPE_MALWARE, name('stray'), { stix_id: strayStix })], { ...chunked, settler: straySettler });
    const strayId = idOf(ENTITY_TYPE_MALWARE, name('stray'));
    check('stray_relations_repointed', (await relationsTouching(strayId, RELATION_USES)).length === N
    && (await relationsTouching(deterministicId(strayStix), RELATION_USES)).length === 0
    && (await denormalizedCount(strayId, inferIndexFromConceptType(ENTITY_TYPE_MALWARE), RELATION_USES)) === N, straySettler.counters);

    // 13. Time range is not part of the identity: copies widen it (today: a new relationship beyond 30 days)
    const timeHub = entity(ENTITY_TYPE_MALWARE, name('time-hub'));
    await writeEntities([timeHub], chunked);
    const timeInput = uses(sid(sources[0].type, sources[0].name), sid(timeHub.type, timeHub.name));
    for (const times of [{ start_time: '2024-01-01T00:00:00.000Z', stop_time: '2024-02-01T00:00:00.000Z' }, { start_time: '2025-06-01T00:00:00.000Z', stop_time: '2025-07-01T00:00:00.000Z' }, {}]) {
      await writeRelations([{ ...timeInput, ...times }], chunked);
    }
    const timeRels = await relationsTouching(idOf(ENTITY_TYPE_MALWARE, timeHub.name), RELATION_USES);
    check('time_range_widened', timeRels.length === 1 && new Date(timeRels[0].start_time).toISOString() === '2024-01-01T00:00:00.000Z'
    && new Date(timeRels[0].stop_time).toISOString() === '2025-07-01T00:00:00.000Z', timeRels.map((r: any) => [r.start_time, r.stop_time]));

    // 14. Re-ingestion: higher confidence replaces, lower confidence does not; markings keep the highest per type
    const mergeHub = entity(ENTITY_TYPE_MALWARE, name('merge-hub'));
    await writeEntities([mergeHub], chunked);
    const mergeInputs = (extra: Partial<RelationInput>) => sources.map((s) => uses(sid(s.type, s.name), sid(mergeHub.type, mergeHub.name), extra));
    await writeRelations(mergeInputs({ description: 'v1', confidence: 50, objectMarking: [MARKING_TLP_GREEN] }), chunked);
    results.reingest_higher_confidence = await writeRelations(mergeInputs({ description: 'v2', confidence: 80, objectMarking: [MARKING_TLP_AMBER] }), single);
    results.reingest_lower_confidence = await writeRelations(mergeInputs({ description: 'v3', confidence: 10 }), single);
    results.reingest_unchanged = await writeRelations(mergeInputs({ description: 'v2', confidence: 80 }), single);
    const mergedRels = await relationsTouching(idOf(ENTITY_TYPE_MALWARE, mergeHub.name), RELATION_USES);
    check('reingest_merges_not_duplicates', mergedRels.length === N && results.reingest_higher_confidence.merged === N);
    check('reingest_confidence_rule', mergedRels.every((r: any) => r.description === 'v2' && r.confidence === 80), [...new Set(mergedRels.map((r: any) => `${r.description}/${r.confidence}`))]);
    check('reingest_unchanged_is_noop', results.reingest_unchanged.writer.relations_unchanged === N);
    check('reingest_markings_highest', mergedRels.every((r: any) => JSON.stringify(r['rel_object-marking.internal_id']) === JSON.stringify([amber.internal_id])));
    check('reingest_update_events', results.reingest_higher_confidence.writer.events_update === N);
    check('reingest_old_marking_meta_removed', (await relationsTouching(green.internal_id, 'object-marking')).every((m: any) => !mergedRels.some((r: any) => m.connections.some((c: any) => c.internal_id === r.internal_id))));

    // 15. Delete: tombstones refuse later references; relationships the platform's delete did not see are removed
    const doomed = entity(ENTITY_TYPE_MALWARE, name('doomed'));
    const doomedSettler = new Settler();
    await writeEntities([doomed], chunked);
    const doomedId = idOf(ENTITY_TYPE_MALWARE, doomed.name);
    await writeRelations(sources.map((s) => uses(sid(s.type, s.name), sid(doomed.type, doomed.name))), { ...chunked, settler: doomedSettler, noSettle: true });
    // The race the settler covers: the platform delete runs before the relationships are searchable
    const doomedDoc = await loadDoc(inferIndexFromConceptType(ENTITY_TYPE_MALWARE), doomedId);
    await setKeys([...identityKeys(ENTITY_TYPE_MALWARE, { name: doomed.name }), doomedId].map((key) => ({ key, owner: { owner_id: doomedId, owner_index: doomedDoc._index, owner_type: ENTITY_TYPE_MALWARE, owner_standard_id: doomedDoc.standard_id }, state: 'deleted' as const })));
    await deleteElementById(testContext, ADMIN_USER, doomedId, ENTITY_TYPE_MALWARE);
    await settleAll([doomedSettler]);
    results.delete_settler = doomedSettler.counters;
    check('delete_removes_unseen_relationships', (await relationsTouching(doomedId, RELATION_USES)).length === 0, doomedSettler.counters);
    const srcAfterDelete = await loadDoc(inferIndexFromConceptType(ENTITY_TYPE_INTRUSION_SET), idOf(ENTITY_TYPE_INTRUSION_SET, sources[0].name));
    check('delete_cleans_other_side_lists', !(srcAfterDelete['rel_uses.internal_id'] ?? []).includes(doomedId));
    results.after_delete = await writeRelations([uses(sid(sources[0].type, sources[0].name), sid(doomed.type, doomed.name))], chunked);
    check('delete_refuses_new_references', results.after_delete.writer.rejected_deleted_ref === 1);
    const gone = entity(ENTITY_TYPE_MALWARE, name('gone'));
    await writeEntities([gone], chunked);
    await deleteEntity({ internal_id: idOf(ENTITY_TYPE_MALWARE, gone.name), _index: inferIndexFromConceptType(ENTITY_TYPE_MALWARE) });
    results.recreate_after_delete = await writeEntities([gone], chunked);
    check('recreate_after_delete', (await entitiesNamed([gone.name])).length === 1 && results.recreate_after_delete.writer.entities_created === 1);

    // 16. Rename through the platform: the old and the new standard ids both resolve to the same object
    const renamed = entity(ENTITY_TYPE_MALWARE, name('before-rename'));
    await writeEntities([renamed], chunked);
    const renamedId = idOf(ENTITY_TYPE_MALWARE, renamed.name);
    await renameEntity({ internal_id: renamedId, _index: inferIndexFromConceptType(ENTITY_TYPE_MALWARE), entity_type: ENTITY_TYPE_MALWARE }, name('after-rename'));
    await writeRelations([
      uses(sid(sources[0].type, sources[0].name), sid(ENTITY_TYPE_MALWARE, name('after-rename'))),
      uses(sid(sources[1].type, sources[1].name), sid(ENTITY_TYPE_MALWARE, name('before-rename'))),
    ], chunked);
    check('rename_both_ids_resolve', (await relationsTouching(renamedId, RELATION_USES)).length === 2);

    // 17. indicates: the target is not impacted, as today (no rel_indicates list on the attack pattern)
    const pattern = entity(ENTITY_TYPE_ATTACK_PATTERN, name('pattern'));
    await writeEntities([pattern], chunked);
    const indicator: any = await addIndicator(testContext, ADMIN_USER, { name: name('indicator'), pattern: `[domain-name:value = '${RUN_ID}.lockfree.example']`, pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } as any);
    await registerExisting([indicator]);
    await writeRelations([{ relationship_type: RELATION_INDICATES, source_ref: indicator.standard_id, target_ref: sid(pattern.type, pattern.name), source_type: 'Indicator', target_type: ENTITY_TYPE_ATTACK_PATTERN }], chunked);
    const patternId = idOf(ENTITY_TYPE_ATTACK_PATTERN, pattern.name);
    check('indicates_target_not_listed', (await denormalizedCount(patternId, inferIndexFromConceptType(ENTITY_TYPE_ATTACK_PATTERN), RELATION_INDICATES)) === 0
    && (await relationsTouching(patternId, RELATION_INDICATES)).length === 1);
    const indicatorDoc = await loadDoc(indicator._index, indicator.internal_id);
    check('indicates_source_listed', (indicatorDoc['rel_indicates.internal_id'] ?? []).includes(patternId));

    // 18. Relationship ids are derived from the ends: the same relationship has the same id everywhere
    check('relationship_id_derived', lfRel.internal_id === deterministicId(relationKey(RELATION_USES, loadedEntity.internal_id, target.internal_id)));

    results.failures = failures;
    writeResults('lockfree-behaviours', results);
    expect(failures).toEqual([]);
  });
});
