// Settler of the lock-free prototype: the work that today happens under the endpoint locks, done afterwards and
// grouped per endpoint. Each flush:
//   1. reconciles duplicates found by lost key races (merge the duplicate into the owner, re-point its keys and
//      relationships, delete it);
//   2. resolves provisional ends: an end that now exists under another id gets its relationships re-pointed,
//      an end whose keys are tombstones gets its relationships deleted;
//   3. appends relationship ends to the rel_* lists of every endpoint that exists, one update per endpoint, and
//      fills the name and types of ends that were provisional.
// Pending work lives in memory here; a real implementation would keep it in a durable queue partitioned by
// endpoint id. Several settlers can run at the same time: updates are scripts with retry_on_conflict, merges use
// if_seq_no.
import * as R from 'ramda';
import { testContext } from '../../utils/testQuery';
import {
  buildDenormalizedRefsScriptParams,
  EL_DENORMALIZED_REFS_SCRIPT_SOURCE,
  elRawBulk,
  elRawSearch,
  elRefreshIndices,
  isImpactedTypeAndSide,
  ROLE_FROM,
  ROLE_TO,
} from '../../../src/database/engine';
import { inferIndexFromConceptType, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../../src/database/utils';
import { getParentTypes } from '../../../src/schema/schemaUtils';
import { buildRefRelationKey, ID_INTERNAL, IDS_STIX } from '../../../src/schema/general';
import { isStixRefRelationship } from '../../../src/schema/stixRefRelationship';
import { now } from '../../../src/utils/format';
import { benchTimer } from '../../../src/utils/bench-timing';
import { deterministicId, identityKeys, lookupKeys, type Owner, setKeys } from './identity';
import {
  add,
  buildMetaRelations,
  bulkCreate,
  bulkDelete,
  type Counters,
  fetchDocs,
  type Incoming,
  mergeInto,
  newCounters,
  prepareDocs,
  REF_FIELDS,
  relationKey,
  resolveRefs,
  standardIdWithoutTime,
  storedShape,
} from './store';
import type { RelationInput } from './writer';

interface EndpointWork {
  index: string;
  type: string;
  byRelation: Map<string, { side: string; ids: Set<string> }>;
}
interface EndRef { internal_id: string; index: string; stix_ref?: string }

const REMOVE_SCRIPT = 'for (r in params.remove) { if (ctx._source[r.field] != null) { ctx._source[r.field].removeIf(x -> r.ids.contains(x)); } }';
const NAMES_SCRIPT = 'for (c in ctx._source.connections) { if (params.ends.containsKey(c.internal_id)) { c.name = params.ends[c.internal_id].name; c.types = params.ends[c.internal_id].types; } }';

export class Settler {
  counters: Counters = newCounters();

  private endpoints = new Map<string, EndpointWork>();

  // relationship id -> its ends, while one end is provisional or its endpoint updates are pending
  private relations = new Map<string, { index: string; type: string; ends: EndRef[]; input?: RelationInput }>();

  private reconciliations: { loser: Owner; winner: Owner }[] = [];

  addEndpoint(endpoint: any, relationType: string, otherId: string, side: string) {
    const entry = this.endpoints.get(endpoint.internal_id) ?? { index: endpoint._index, type: endpoint.entity_type, byRelation: new Map() };
    const ref = entry.byRelation.get(relationType) ?? { side, ids: new Set<string>() };
    ref.ids.add(otherId);
    entry.byRelation.set(relationType, ref);
    this.endpoints.set(endpoint.internal_id, entry);
  }

  addRelation(relation: any, from: any, to: any, input?: RelationInput) {
    const type = relation.relationship_type;
    if (isImpactedTypeAndSide(type, from.entity_type, to.entity_type, ROLE_FROM)) this.addEndpoint(from, type, to.internal_id, 'from');
    if (isImpactedTypeAndSide(type, from.entity_type, to.entity_type, ROLE_TO)) this.addEndpoint(to, type, from.internal_id, 'to');
    this.relations.set(relation.internal_id, {
      index: relation._index,
      type,
      input,
      ends: [
        { internal_id: from.internal_id, index: from._index, stix_ref: from.i_provisional ? from.standard_id : undefined },
        { internal_id: to.internal_id, index: to._index, stix_ref: to.i_provisional ? to.standard_id : undefined },
      ],
    });
  }

  reconcile(loser: Owner, winner: Owner) {
    if (loser.owner_id !== winner.owner_id) this.reconciliations.push({ loser, winner });
  }

  get pending() {
    return this.endpoints.size + [...this.relations.values()].filter((r) => r.ends.some((e) => e.stix_ref)).length + this.reconciliations.length;
  }

  async flush() {
    const bench = benchTimer('lf_settle');
    add(this.counters, 'flushes');
    const reconciliations = R.uniqBy((r) => `${r.loser.owner_id}|${r.winner.owner_id}`, this.reconciliations.splice(0));
    for (const r of reconciliations) await this.reconcileOne(r.loser, r.winner);
    bench.step('reconcile');
    await this.resolveEnds();
    bench.step('resolve_ends');
    await this.applyEndpoints();
    bench.step('endpoints');
    bench.total();
  }

  // Ends: existing ones settle, provisional ones known under another id are re-pointed, deleted ones are removed
  private async resolveEnds() {
    const ends = new Map<string, EndRef>();
    this.relations.forEach((r) => r.ends.forEach((e) => ends.set(e.internal_id, e)));
    this.endpoints.forEach((w, id) => {
      if (!ends.has(id)) ends.set(id, { internal_id: id, index: w.index });
    });
    if (ends.size === 0) return;
    const found = await fetchDocs([...ends.values()].map((e) => ({ index: e.index, id: e.internal_id })), { light: true });
    const missing = [...ends.values()].filter((e) => !found.has(e.internal_id));
    const owners = await lookupKeys(missing.flatMap((e) => [e.internal_id, ...(e.stix_ref ? [e.stix_ref] : [])]));
    for (const end of missing) {
      const byStix = end.stix_ref ? owners.get(end.stix_ref) : undefined;
      const byId = owners.get(end.internal_id);
      if (byStix?.state === 'live' && byStix.owner_id !== end.internal_id) {
        const target = (await fetchDocs([{ index: byStix.owner_index, id: byStix.owner_id }], { light: true })).get(byStix.owner_id);
        if (target) await this.repointRelationsOf(end.internal_id, target);
      } else if (byStix?.state === 'deleted' || byId?.state === 'deleted') {
        await this.deleteRelationsOf(end.internal_id);
      }
    }
    // Ends that exist under their provisional id: fill the name and types they lacked
    const body: any[] = [];
    this.relations.forEach((r, relationId) => {
      const provisional = r.ends.filter((e) => e.stix_ref);
      if (provisional.length === 0 || !provisional.every((e) => found.has(e.internal_id))) return;
      const params = { ends: Object.fromEntries(provisional.map((e) => {
        const doc = found.get(e.internal_id);
        return [e.internal_id, { name: doc.name, types: [doc.entity_type, ...getParentTypes(doc.entity_type)] }];
      })) };
      body.push({ update: { _index: r.index, _id: relationId, retry_on_conflict: 5 } }, { script: { source: NAMES_SCRIPT, params } });
      r.ends.forEach((e) => {
        e.stix_ref = undefined;
      });
      add(this.counters, 'names_filled');
    });
    await this.bulk(body);
  }

  // One update per endpoint that exists, with every id collected for it since the last flush
  private async applyEndpoints() {
    if (this.endpoints.size === 0) return;
    const found = await fetchDocs([...this.endpoints.entries()].map(([id, w]) => ({ index: w.index, id })), { light: true });
    const body: any[] = [];
    const updatedAt = now();
    [...this.endpoints.entries()].filter(([id]) => found.has(id)).forEach(([id, work]) => {
      const targets = [...work.byRelation.entries()].map(([relation, ref]) => ({
        relation,
        field: ID_INTERNAL,
        elements: [...ref.ids].map((otherId) => ({ id: otherId, side: ref.side, type: work.type })),
      }));
      const params = buildDenormalizedRefsScriptParams(targets, updatedAt);
      // Distinct: a relationship merged or re-sent never lists the same end twice
      params.distinct_refs = [...params.distinct_refs, ...params.appended_refs];
      params.appended_refs = [];
      body.push({ update: { _index: found.get(id)._index, _id: id, retry_on_conflict: 10 } }, { script: { source: EL_DENORMALIZED_REFS_SCRIPT_SOURCE, params } });
      this.endpoints.delete(id);
      add(this.counters, 'endpoint_updates');
    });
    await this.bulk(body);
    // Relationships whose ends are all settled are no longer tracked
    this.relations.forEach((r, relationId) => {
      if (r.ends.every((e) => !e.stix_ref && !this.endpoints.has(e.internal_id))) this.relations.delete(relationId);
    });
  }

  private async bulk(body: any[]) {
    for (const chunk of R.splitEvery(2000, body)) {
      const response: any = await elRawBulk(testContext, { refresh: false, body: chunk });
      const failed = response.items.find((i: any) => {
        const item: any = Object.values(i)[0];
        return item.status >= 300 && item.status !== 404;
      });
      if (failed) throw new Error(`Settle failed: ${JSON.stringify(failed)}`);
    }
  }

  // Relationships stored with a provisional end id, found through this settler's tracking
  private trackedRelationsOf(endId: string) {
    return [...this.relations.entries()].filter(([, r]) => r.ends.some((e) => e.internal_id === endId)).map(([id, r]) => ({ id, ...r }));
  }

  // Pending list updates naming an end that moved or was deleted: replace or drop the id before they are applied
  private replacePendingId(oldId: string, newId?: string) {
    this.endpoints.forEach((work) => work.byRelation.forEach((ref) => {
      if (ref.ids.delete(oldId) && newId) ref.ids.add(newId);
    }));
  }

  private async repointRelationsOf(oldEndId: string, target: any) {
    this.replacePendingId(oldEndId, target.internal_id);
    const tracked = this.trackedRelationsOf(oldEndId);
    const docs = await fetchDocs(tracked.map((t) => ({ index: t.index, id: t.id })));
    for (const t of tracked) {
      const doc = docs.get(t.id);
      if (doc) await this.repoint(doc, oldEndId, target);
      this.relations.delete(t.id);
    }
    this.endpoints.delete(oldEndId);
  }

  private async deleteRelationsOf(endId: string) {
    this.replacePendingId(endId);
    const tracked = this.trackedRelationsOf(endId);
    const docs = await fetchDocs(tracked.map((t) => ({ index: t.index, id: t.id })));
    for (const t of tracked) {
      const doc = docs.get(t.id);
      if (doc) await this.deleteRelation(doc);
      this.relations.delete(t.id);
    }
    this.endpoints.delete(endId);
  }

  private metaIdsOf(relation: any) {
    return REF_FIELDS.flatMap((ref) => (relation[buildRefRelationKey(ref.relation)] ?? []).map((targetId: string) => ({
      index: inferIndexFromConceptType(ref.relation),
      id: deterministicId(`${ref.relation}|${relation.internal_id}|${targetId}`),
    })));
  }

  // Remove an id from the rel_<type> list of an endpoint (the other end of a moved or deleted relationship)
  private async removeFromEndpoint(endpoint: { internal_id: string; index: string }, relationType: string, ids: string[]) {
    await this.bulk([
      { update: { _index: endpoint.index, _id: endpoint.internal_id, retry_on_conflict: 10 } },
      { script: { source: REMOVE_SCRIPT, params: { remove: [{ field: buildRefRelationKey(relationType), ids }] } } },
    ]);
  }

  private async deleteRelation(relation: any) {
    const ends = relation.connections.map((c: any) => ({ internal_id: c.internal_id, index: inferIndexFromConceptType(c.types[0]) }));
    await bulkDelete([{ index: relation._index, id: relation.internal_id }, ...this.metaIdsOf(relation)]);
    for (const end of ends) {
      const other = ends.find((e: any) => e.internal_id !== end.internal_id);
      if (other) await this.removeFromEndpoint(end, relation.entity_type, [other.internal_id]);
    }
    add(this.counters, 'relations_deleted_dangling');
  }

  // Move a relationship from one end to another: the id follows the ends, so it is a new document. If one
  // already exists (the same relationship sent with the other id), the moved copy merges into it.
  private async repoint(relation: any, oldEndId: string, target: any) {
    const connections = relation.connections.map((c: any) => (c.internal_id === oldEndId
      ? { ...c, internal_id: target.internal_id, name: target.name, types: [target.entity_type, ...getParentTypes(target.entity_type)] }
      : c));
    const fromConn = connections.find((c: any) => c.role.endsWith('_from'));
    const toConn = connections.find((c: any) => c.role.endsWith('_to'));
    const type = relation.entity_type;
    const newId = deterministicId(relationKey(type, fromConn.internal_id, toConn.internal_id));
    const ends = await fetchDocs(connections.map((c: any) => ({ index: inferIndexFromConceptType(c.types[0]), id: c.internal_id })), { light: true });
    const from = ends.get(fromConn.internal_id);
    const to = ends.get(toConn.internal_id);
    const standardId = from && to ? standardIdWithoutTime(type, from, to) : relation.standard_id;
    const moved = {
      ...storedShape(relation),
      internal_id: newId,
      standard_id: standardId,
      [IDS_STIX]: R.uniq([...(relation[IDS_STIX] ?? []), relation.standard_id]).filter((s) => s !== standardId),
      connections,
    };
    const [status] = await bulkCreate([{ ...moved, _index: relation._index }]);
    const refIds = REF_FIELDS.flatMap((ref) => relation[buildRefRelationKey(ref.relation)] ?? []);
    const refs = await resolveRefs(refIds);
    if (status === 201) {
      const source = { ...moved, id: newId, entity_type: type, base_type: 'RELATION', parent_types: getParentTypes(type), _index: relation._index };
      const metas = REF_FIELDS.flatMap((ref) => {
        const targets = (relation[buildRefRelationKey(ref.relation)] ?? []).map((id: string) => refs.get(id)).filter(Boolean);
        return targets.length ? buildMetaRelations(source, ref.relation, targets) : [];
      });
      await bulkCreate(await prepareDocs(metas));
    } else {
      const incoming: Incoming = {
        description: relation.description,
        confidence: relation.confidence,
        start_time: relation.start_time,
        stop_time: relation.stop_time,
        stix_ids: [relation.standard_id, ...(relation[IDS_STIX] ?? [])],
        refs: Object.fromEntries(REF_FIELDS.map((ref) => {
          const objects = (relation[buildRefRelationKey(ref.relation)] ?? []).map((id: string) => refs.get(id)).filter(Boolean);
          return [ref.input, ref.multiple ? objects : objects[0]];
        })),
      };
      await mergeInto(relation._index, newId, incoming, this.counters);
    }
    await bulkDelete([{ index: relation._index, id: relation.internal_id }, ...this.metaIdsOf(relation)]);
    // Endpoint lists: the other end listed the old end, the new end must list the other end
    const other = connections.find((c: any) => c.internal_id !== target.internal_id);
    if (other && isImpactedTypeAndSide(type, from?.entity_type ?? fromConn.types[0], to?.entity_type ?? toConn.types[0], other.role.endsWith('_from') ? ROLE_FROM : ROLE_TO)) {
      await this.removeFromEndpoint({ internal_id: other.internal_id, index: inferIndexFromConceptType(other.types[0]) }, type, [oldEndId]);
      this.addEndpoint({ internal_id: other.internal_id, _index: inferIndexFromConceptType(other.types[0]), entity_type: other.types[0] }, type, target.internal_id, other.role.endsWith('_from') ? 'from' : 'to');
    }
    const targetSide = fromConn.internal_id === target.internal_id ? ROLE_FROM : ROLE_TO;
    if (other && isImpactedTypeAndSide(type, from?.entity_type ?? fromConn.types[0], to?.entity_type ?? toConn.types[0], targetSide)) {
      this.addEndpoint(target, type, other.internal_id, targetSide === ROLE_FROM ? 'from' : 'to');
    }
    add(this.counters, 'relations_repointed');
  }

  // A duplicate entity found after both were created: merge it into the owner and remove it
  private async reconcileOne(loser: Owner, winner: Owner) {
    const docs = await fetchDocs([{ index: loser.owner_index, id: loser.owner_id }, { index: winner.owner_index, id: winner.owner_id }]);
    const lost = docs.get(loser.owner_id);
    const kept = docs.get(winner.owner_id);
    if (!lost || !kept) return;
    const refIds = REF_FIELDS.flatMap((ref) => lost[buildRefRelationKey(ref.relation)] ?? []);
    const refs = await resolveRefs(refIds);
    await mergeInto(kept._index, kept.internal_id, {
      name: lost.name,
      aliases: lost.aliases ?? lost.x_opencti_aliases ?? [],
      stix_ids: [lost.standard_id, ...(lost[IDS_STIX] ?? [])],
      description: lost.description,
      confidence: lost.confidence,
      refs: Object.fromEntries(REF_FIELDS.map((ref) => {
        const objects = (lost[buildRefRelationKey(ref.relation)] ?? []).map((id: string) => refs.get(id)).filter(Boolean);
        return [ref.input, ref.multiple ? objects : objects[0]];
      })),
    }, this.counters);
    const keys = [...identityKeys(lost.entity_type, { ...lost, stix_id: lost.standard_id }), lost.internal_id];
    await setKeys(keys.map((key) => ({ key, owner: R.omit(['key', 'state'], winner) })));
    // Its relationships: the only search of the prototype, on a rare path, after a refresh
    await elRefreshIndices(READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED);
    const response: any = await elRawSearch(testContext, null as any, null, {
      index: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
      size: 10000,
      body: { query: { nested: { path: 'connections', query: { term: { 'connections.internal_id.keyword': lost.internal_id } } } } },
    });
    const hits = response.hits.hits.map((h: any) => ({ ...h._source, id: h._source.internal_id, _index: h._index, i_source_keys: Object.keys(h._source) }));
    for (const relation of hits) {
      const ownRef = isStixRefRelationship(relation.entity_type) && relation.connections.some((c: any) => c.internal_id === lost.internal_id && c.role.endsWith('_from'));
      if (ownRef) await bulkDelete([{ index: relation._index, id: relation.internal_id }]);
      else await this.repoint(relation, lost.internal_id, kept);
    }
    await bulkDelete([{ index: lost._index, id: lost.internal_id }]);
    this.replacePendingId(lost.internal_id, kept.internal_id);
    this.endpoints.delete(lost.internal_id);
    add(this.counters, 'entities_reconciled');
  }
}
