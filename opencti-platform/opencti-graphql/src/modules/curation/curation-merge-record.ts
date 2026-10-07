import * as R from 'ramda';
import conf, { BUS_TOPICS, booleanConf, logApp } from '../../config/conf';
import { DatabaseError, FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreObject, StoreObject, StoreRelation } from '../../types/store';
import type { MergeCommitInput, MergePreparationInput, MergeRecorder } from '../../database/merge-hooks';
import {
  createEntity,
  createRelation,
  deleteElementById,
  patchAttribute,
  repointRelationships,
  restoreEntityFromMergeSnapshot,
  storeLoadByIdsWithRefs,
  storeLoadByIdWithRefs,
  updateAttribute,
} from '../../database/middleware';
import { fullEntitiesList, fullRelationsList, internalFindByIds, pageEntitiesConnection, storeLoadById, type EntityOptions } from '../../database/middleware-loader';
import { lockResources } from '../../lock/master-lock';
import { getDraftContext } from '../../utils/draftContext';
import { SYSTEM_USER } from '../../utils/access';
import { controlUserConfidenceAgainstElement } from '../../utils/confidence-level';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { isInferredIndex, isNotEmptyField } from '../../database/utils';
import { schemaAttributesDefinition, isMultipleAttribute } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { getInputIds } from '../../schema/identifier';
import { isStixRefRelationship, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { ABSTRACT_STIX_CORE_OBJECT, INPUT_GRANTED_REFS, INPUT_MARKINGS } from '../../schema/general';
import { type EditInput, EditOperation, FilterMode, FilterOperator } from '../../generated/graphql';
import { isEnterpriseEditionFromSettings } from '../../enterprise-edition/ee';
import { getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';
import { computeSubjectRestrictions, intersectGrantedOrganizations, markProposalReverted } from './curation-proposals';
import { copyFile, deleteFile, loadFile, storeFileConverter } from '../../database/file-storage';
import { addCurationMergeRecordCount, addCurationUnmergeCount } from '../../manager/telemetryManager';
import { now } from '../../utils/format';
import {
  type AliasProvenance,
  type BasicStoreEntityMergeRecord,
  ENTITY_TYPE_MERGE_RECORD,
  IRREVERSIBLE_FILE_NAME_COLLISION,
  IRREVERSIBLE_FILE_NOT_MOVED,
  IRREVERSIBLE_MERGE_INTERRUPTED,
  IRREVERSIBLE_MERGED_ENTITY_DELETED,
  IRREVERSIBLE_RETENTION_OVER,
  IRREVERSIBLE_TOO_MANY_MOVED_RELATIONSHIPS,
  IRREVERSIBLE_TOO_MANY_REMOVED_RELATIONSHIPS,
  MERGE_STATUS_ACTIVE,
  MERGE_STATUS_IRREVERSIBLE,
  MERGE_STATUS_PARTIALLY_REVERTED,
  MERGE_STATUS_PENDING,
  MERGE_STATUS_REVERTED,
  type MergeRecreatableRelationship,
  type MergeRedirectedRelationship,
  type MergeSnapshot,
  type MergeSnapshotRef,
  type MergeSourceSnapshot,
  type MergeTargetSnapshot,
} from './curation-types';
import { computeTargetRevertInputs, isIrrecoverableRecreationError, isSnapshotAttribute } from './curation-merge-diff';
import { getCurationSettings } from './curation-settings';
import { FIELD_AUTHORITY_ATTRIBUTE } from './curation-field-authority';
import { keepWithReadableParticipants, pageWithReadableParticipants } from './curation-readability';

const MERGE_RECORDS_ENABLED = booleanConf('curation:merge_records_enabled', true);
const MAX_RECREATABLE_RELATIONSHIPS = Number(conf.get('curation:merge_record_max_recreatable_relationships') ?? 10000);
const MAX_REDIRECTED_RELATIONSHIPS = Number(conf.get('curation:merge_record_max_redirected_relationships') ?? 100000);
const SNAPSHOT_LOAD_BATCH = 500;
const EXPIRY_PAGE_SIZE = 500;

// region snapshots
export const snapshotAttributes = (instance: Record<string, any>): Record<string, unknown> => {
  const attributes: Record<string, unknown> = {};
  schemaAttributesDefinition.getAttributeNames(instance.entity_type).forEach((key) => {
    const value = instance[key];
    if (isSnapshotAttribute(key) && value !== undefined && value !== null) {
      attributes[key] = value;
    }
  });
  if (isNotEmptyField(instance.creator_id)) {
    attributes.creator_id = instance.creator_id;
  }
  // A restored entity gets back the source of each governed value, or the next upserts would rank its author instead.
  // It is never written back on the target: the revert skips internal fields.
  if (isNotEmptyField(instance[FIELD_AUTHORITY_ATTRIBUTE])) {
    attributes[FIELD_AUTHORITY_ATTRIBUTE] = instance[FIELD_AUTHORITY_ATTRIBUTE];
  }
  return attributes;
};

const refValueToIds = (value: unknown): string | string[] | null => {
  if (value === undefined || value === null) return null;
  if (Array.isArray(value)) {
    return value.map((v) => (typeof v === 'string' ? v : (v as BasicStoreBase)?.internal_id)).filter((id): id is string => typeof id === 'string');
  }
  if (typeof value === 'string') return value;
  return (value as BasicStoreBase).internal_id ?? null;
};

export const snapshotRefs = (instance: Record<string, any>): MergeSnapshotRef => {
  const refs: MergeSnapshotRef = {};
  schemaRelationsRefDefinition.getRelationsRef(instance.entity_type).forEach((ref) => {
    const value = refValueToIds(instance[ref.name] ?? instance[ref.databaseName]);
    if (value !== null && !(Array.isArray(value) && value.length === 0)) {
      refs[ref.name] = value;
    }
  });
  return refs;
};

const nameOf = (element: unknown): string | undefined => (element as { name?: string } | undefined)?.name;

const aliasesOf = (instance: Record<string, any>): string[] => [...(instance.aliases ?? []), ...(instance.x_opencti_aliases ?? [])];

interface MergeRecordPreparation {
  recordId: string;
  target: MergeTargetSnapshot;
  sources: MergeSourceSnapshot[];
  irreversibleReason: string | null;
}

const entityFilesPath = (entity: { entity_type: string; internal_id: string }) => `/${entity.entity_type}/${entity.internal_id}/`;

// Files of a source that the merge moves under the target: same name, unless the target already has a file with it.
const predictMovedFileIds = (source: BasicStoreObject, target: BasicStoreObject): string[] => {
  const targetFileIds = new Set((target.x_opencti_files ?? []).map((file) => file.id));
  return (source.x_opencti_files ?? [])
    .map((file) => file.id.replace(entityFilesPath(source), entityFilesPath(target)))
    .filter((id) => id.includes(entityFilesPath(target)) && !targetFileIds.has(id));
};

// The files are moved source after source, and a source file is not moved when the target already has a file with its
// name, its own or one moved from another source: the merge deletes it with the source, and no unmerge can bring it back.
export const hasFileNameCollision = (sources: BasicStoreObject[], target: BasicStoreObject) => {
  const destinations = new Set((target.x_opencti_files ?? []).map((file) => file.id));
  return sources.some((source) => (source.x_opencti_files ?? []).some((file) => {
    const destination = file.id.replace(entityFilesPath(source), entityFilesPath(target));
    if (destinations.has(destination)) return true;
    destinations.add(destination);
    return false;
  }));
};

const loadRecreatableRelationships = async (context: AuthContext, ids: string[]): Promise<Map<string, MergeRecreatableRelationship>> => {
  const result = new Map<string, MergeRecreatableRelationship>();
  const batches = R.splitEvery(SNAPSHOT_LOAD_BATCH, ids);
  for (let index = 0; index < batches.length; index += 1) {
    const relations = await storeLoadByIdsWithRefs<StoreRelation>(context, SYSTEM_USER, batches[index]);
    relations.forEach((relation) => {
      result.set(relation.internal_id, {
        id: relation.internal_id,
        standard_id: relation.standard_id,
        entity_type: relation.entity_type,
        from_id: relation.fromId,
        from_type: relation.fromType,
        to_id: relation.toId,
        to_type: relation.toType,
        attributes: snapshotAttributes(relation),
        refs: snapshotRefs(relation),
      });
    });
  }
  return result;
};

const prepareMergeRecord = async (context: AuthContext, user: AuthUser, input: MergePreparationInput): Promise<MergeRecordPreparation | null> => {
  if (getDraftContext(context, user)) {
    // Merges inside a draft are reverted with the draft itself.
    return null;
  }
  const { target, sources, sourcesDependencies, plan, metadata } = input;
  const sourceIds = new Set(sources.map((source) => source.internal_id));
  const fromRedirectedIds = new Set(plan.fromRedirects.map((dependency) => dependency.i_relation.internal_id));
  const toRedirectedIds = new Set(plan.toRedirects.map((dependency) => dependency.i_relation.internal_id));
  // A relationship between two sources survives the merge only when both of its sides move to the target: moved on one
  // side only, it still points to the other source and is deleted with it, so it is recreated by the unmerge.
  const survivesMerge = (relation: { internal_id: string; fromId: string; toId: string }) => (sourceIds.has(relation.fromId) && sourceIds.has(relation.toId)
    ? fromRedirectedIds.has(relation.internal_id) && toRedirectedIds.has(relation.internal_id)
    : fromRedirectedIds.has(relation.internal_id) || toRedirectedIds.has(relation.internal_id));
  let irreversibleReason: string | null = null;
  const sourceSnapshots: MergeSourceSnapshot[] = [];
  const recreatableIdsBySource = new Map<string, string[]>();
  const targetAliasKeys = new Set([nameOf(target), ...aliasesOf(target)].filter((v): v is string => typeof v === 'string' && v.length > 0).map((v) => v.toLowerCase()));
  const targetStixIds = new Set([target.standard_id, ...(target.x_opencti_stix_ids ?? [])]);
  sources.forEach((source) => {
    const redirected: MergeRedirectedRelationship[] = [];
    plan.fromRedirects.forEach(({ i_relation: relation }) => {
      if (relation.fromId === source.internal_id && !isStixRefRelationship(relation.entity_type) && !isInferredIndex(relation._index) && survivesMerge(relation)) {
        redirected.push({ id: relation.internal_id, entity_type: relation.entity_type, side: 'from', other_id: relation.toId, other_type: relation.toType });
      }
    });
    plan.toRedirects.forEach(({ i_relation: relation }) => {
      if (relation.toId === source.internal_id && !isInferredIndex(relation._index) && survivesMerge(relation)) {
        redirected.push({ id: relation.internal_id, entity_type: relation.entity_type, side: 'to', other_id: relation.fromId, other_type: relation.fromType });
      }
    });
    const recreatableIds = R.uniq([
      ...sourcesDependencies.i_relations_from
        .filter(({ i_relation: relation }) => relation.fromId === source.internal_id && !isStixRefRelationship(relation.entity_type))
        .map(({ i_relation: relation }) => relation),
      ...sourcesDependencies.i_relations_to
        .filter(({ i_relation: relation }) => relation.toId === source.internal_id)
        .map(({ i_relation: relation }) => relation),
    ].filter((relation) => !survivesMerge(relation) && !isInferredIndex(relation._index)).map((relation) => relation.internal_id));
    recreatableIdsBySource.set(source.internal_id, recreatableIds);
    const sourceNames = [nameOf(source), ...aliasesOf(source)].filter(Boolean) as string[];
    sourceSnapshots.push({
      internal_id: source.internal_id,
      standard_id: source.standard_id,
      entity_type: source.entity_type,
      name: nameOf(source) ?? source.standard_id,
      attributes: snapshotAttributes(source),
      refs: snapshotRefs(source),
      redirected,
      recreatable: [],
      moved_file_ids: predictMovedFileIds(source, target),
      contributed_aliases: R.uniq(sourceNames.filter((name) => !targetAliasKeys.has(name.toLowerCase()))),
      contributed_stix_ids: [source.standard_id, ...(source.x_opencti_stix_ids ?? [])].filter((id) => !targetStixIds.has(id)),
      reverted_at: null,
    });
  });
  const totalRedirected = sourceSnapshots.reduce((acc, snapshot) => acc + snapshot.redirected.length, 0);
  // A relationship between two sources is listed by both of them: it is counted, and recreated, once.
  const allRecreatableIds = R.uniq([...recreatableIdsBySource.values()].flat());
  if (hasFileNameCollision(sources, target)) {
    irreversibleReason = IRREVERSIBLE_FILE_NAME_COLLISION;
    logApp.info('[CURATION] Merge recorded as not reversible: a merged file has the name of a file of the target or of another source', { target_id: target.internal_id });
  } else if (allRecreatableIds.length > MAX_RECREATABLE_RELATIONSHIPS) {
    irreversibleReason = IRREVERSIBLE_TOO_MANY_REMOVED_RELATIONSHIPS;
    logApp.info('[CURATION] Merge recorded as not reversible: too many duplicated relationships removed', { count: allRecreatableIds.length, limit: MAX_RECREATABLE_RELATIONSHIPS });
  } else if (totalRedirected > MAX_REDIRECTED_RELATIONSHIPS) {
    irreversibleReason = IRREVERSIBLE_TOO_MANY_MOVED_RELATIONSHIPS;
    logApp.info('[CURATION] Merge recorded as not reversible: too many relationships moved', { count: totalRedirected, limit: MAX_REDIRECTED_RELATIONSHIPS });
  } else {
    const recreatable = await loadRecreatableRelationships(context, allRecreatableIds);
    sourceSnapshots.forEach((snapshot) => {
      const ids = recreatableIdsBySource.get(snapshot.internal_id) ?? [];

      snapshot.recreatable = ids.map((id) => recreatable.get(id)).filter((relation): relation is MergeRecreatableRelationship => relation !== undefined);
    });
  }
  if (irreversibleReason) {
    sourceSnapshots.forEach((snapshot) => {
      snapshot.redirected = [];
    });
  }
  const aliasProvenance: AliasProvenance[] = sourceSnapshots.map((snapshot) => ({
    alias: snapshot.name,
    source_id: snapshot.internal_id,
    source_aliases: aliasesOf(snapshot.attributes),
    relationship_ids: snapshot.redirected.map((relation) => relation.id),
  }));
  const targetSnapshot: MergeTargetSnapshot = {
    internal_id: target.internal_id,
    standard_id: target.standard_id,
    entity_type: target.entity_type,
    name: nameOf(target) ?? target.standard_id,
    attributes: snapshotAttributes(target),
    refs: snapshotRefs(target),
    post_attributes: {},
    post_refs: {},
    taken_from_source_id: sources[0]?.internal_id ?? null,
  };
  const settings = await getCurationSettings(context);
  const reversibleUntil = new Date(Date.now() + settings.merge_record_retention_days * 24 * 3600 * 1000).toISOString();
  // The record holds a copy of every participant: a reader needs the markings of all of them, and only the
  // organizations every restricted participant is shared with may read it (as for proposals), so that a merge across
  // organizations never reveals the snapshot of one participant to the readers of another.
  const participants = [targetSnapshot, ...sourceSnapshots];
  const refIdsOf = (refs: MergeSnapshotRef, name: string) => (refs[name] as string[] | undefined) ?? [];
  const platformSettings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const record = {
    name: `${targetSnapshot.name} <- ${sourceSnapshots.map((s) => s.name).join(', ')}`,
    merge_target_id: target.internal_id,
    merge_target_type: target.entity_type,
    merge_target_name: targetSnapshot.name,
    merge_source_ids: sourceSnapshots.map((s) => s.internal_id),
    merge_source_names: sourceSnapshots.map((s) => s.name ?? s.standard_id),
    merge_status: MERGE_STATUS_PENDING,
    merge_snapshot: { target: targetSnapshot, sources: sourceSnapshots },
    alias_provenance: aliasProvenance,
    reversible_until: reversibleUntil,
    irreversible_reason: irreversibleReason,
    relationships_redirected_count: sourceSnapshots.reduce((acc, s) => acc + s.redirected.length, 0),
    relationships_recreatable_count: R.uniq(sourceSnapshots.flatMap((s) => s.recreatable.map((relationship) => relationship.id))).length,
    merged_by_id: user.id,
    proposal_id: metadata?.proposal_id ?? null,
    objectMarking: R.uniq(participants.flatMap((participant) => refIdsOf(participant.refs, INPUT_MARKINGS))),
    objectOrganization: intersectGrantedOrganizations(
      participants.map((participant) => refIdsOf(participant.refs, INPUT_GRANTED_REFS)),
      platformSettings?.platform_organization,
    ),
  };
  // Created by the system user: the record carries the restrictions of every merged element, which the merging
  // user may not be allowed to set (organization sharing), while merged_by_id keeps who merged.
  const created = await createEntity(context, SYSTEM_USER, record, ENTITY_TYPE_MERGE_RECORD);
  return { recordId: created.internal_id, target: targetSnapshot, sources: sourceSnapshots, irreversibleReason };
};

/**
 * Turn a pending record into an active one: the state of the merged entity right after the merge is what allows the
 * unmerge to tell the values the merge brought from the values the target already had.
 */
const completeMergeRecord = async (
  context: AuthContext,
  recordId: string,
  target: MergeTargetSnapshot,
  sources: MergeSourceSnapshot[],
  mergedInstance: StoreObject,
  irreversibleReason: string | null,
) => {
  const mergedName = nameOf(mergedInstance) ?? mergedInstance.standard_id;
  const snapshot: MergeSnapshot = {
    target: { ...target, post_attributes: snapshotAttributes(mergedInstance), post_refs: snapshotRefs(mergedInstance) },
    sources,
  };
  await patchAttribute(context, SYSTEM_USER, recordId, ENTITY_TYPE_MERGE_RECORD, {
    name: `${mergedName} <- ${sources.map((s) => s.name).join(', ')}`,
    merge_target_name: mergedName,
    merge_status: irreversibleReason ? MERGE_STATUS_IRREVERSIBLE : MERGE_STATUS_ACTIVE,
    irreversible_reason: irreversibleReason,
    merge_snapshot: snapshot,
  });
  // Counts the merges that can be undone: a merge recorded as not reversible is no reversible merge record.
  if (!irreversibleReason) {
    await addCurationMergeRecordCount();
  }
};

/**
 * A merge that could not copy a file of a source deletes it with the source, and no unmerge can bring it back: a file
 * planned to move that is not under the merged entity makes the record not reversible.
 */
const completedIrreversibleReason = (
  reason: string | null,
  planned: MergeSourceSnapshot[],
  moved: MergeSourceSnapshot[],
  mergedInstance: StoreObject,
): string | null => {
  if (reason) return reason;
  const lostFile = planned.some((snapshot, index) => snapshot.moved_file_ids.some((fileId) => !moved[index].moved_file_ids.includes(fileId)));
  if (!lostFile) return null;
  logApp.warn('[CURATION] Merge recorded as not reversible: a merged file could not be moved to the target', { target_id: mergedInstance.internal_id });
  return IRREVERSIBLE_FILE_NOT_MOVED;
};

const commitMergeRecord = async (context: AuthContext, _user: AuthUser, preparation: MergeRecordPreparation | null, input: MergeCommitInput) => {
  if (!preparation) {
    return;
  }
  const { mergedInstance, sources } = input;
  const targetPathMarker = entityFilesPath(mergedInstance);
  const sourcesById = new Map(sources.map((source) => [source.internal_id, source]));
  const sourceSnapshots = preparation.sources.map((snapshot) => {
    const mutated = sourcesById.get(snapshot.internal_id);
    const movedFileIds = (mutated?.x_opencti_files ?? []).map((file) => file.id).filter((id) => id.includes(targetPathMarker));
    return { ...snapshot, moved_file_ids: movedFileIds };
  });
  const irreversibleReason = completedIrreversibleReason(preparation.irreversibleReason, preparation.sources, sourceSnapshots, mergedInstance);
  await completeMergeRecord(context, preparation.recordId, preparation.target, sourceSnapshots, mergedInstance, irreversibleReason);
};

/** Marks the record right before the first write of the merge: from then on, the graph may differ from the snapshot. */
const startMergeRecord = async (context: AuthContext, preparation: MergeRecordPreparation | null) => {
  if (!preparation) {
    return;
  }
  await patchAttribute(context, SYSTEM_USER, preparation.recordId, ENTITY_TYPE_MERGE_RECORD, { merge_started_at: now() });
};

/** A merge that failed before its first write changed nothing: its record is discarded. */
const abortMergeRecord = async (context: AuthContext, preparation: MergeRecordPreparation | null) => {
  if (!preparation) {
    return;
  }
  await deleteElementById(context, SYSTEM_USER, preparation.recordId, ENTITY_TYPE_MERGE_RECORD);
};

/**
 * A merge that failed after it started writing may have moved files, redirected relationships or updated the target:
 * the record keeps the pre-merge snapshot, the only trace of the previous state, and cannot be undone automatically.
 */
const interruptMergeRecord = async (context: AuthContext, preparation: MergeRecordPreparation | null) => {
  if (!preparation) {
    return;
  }
  await patchAttribute(context, SYSTEM_USER, preparation.recordId, ENTITY_TYPE_MERGE_RECORD, {
    merge_status: MERGE_STATUS_IRREVERSIBLE,
    irreversible_reason: IRREVERSIBLE_MERGE_INTERRUPTED,
  });
};

export const curationMergeRecorder: MergeRecorder<MergeRecordPreparation | null> = {
  isEnabled: () => MERGE_RECORDS_ENABLED,
  prepare: prepareMergeRecord,
  start: startMergeRecord,
  commit: commitMergeRecord,
  abort: abortMergeRecord,
  interrupt: interruptMergeRecord,
};

const PENDING_RECORD_GRACE_MS = 10 * 60 * 1000;

/**
 * Complete the records left pending by a merge whose completion step failed (or by a stopped platform), from the
 * live graph: merged sources are gone, so the merge ran and the record becomes active; a record never marked as
 * started, with every source still there, belongs to a merge that stopped before its first write and is discarded;
 * any other state (a merge that started writing, sources partly gone) cannot be reverted safely and is kept as such.
 */
export const completePendingMergeRecords = async (context: AuthContext) => {
  const filters = {
    mode: 'and' as const,
    filters: [
      { key: ['merge_status'], values: [MERGE_STATUS_PENDING] },
      { key: ['created_at'], values: [new Date(Date.now() - PENDING_RECORD_GRACE_MS).toISOString()], operator: 'lt' as const },
    ],
    filterGroups: [],
  };
  const pending = await pageEntitiesConnection<BasicStoreEntityMergeRecord>(context, SYSTEM_USER, [ENTITY_TYPE_MERGE_RECORD], { filters: filters as any, first: 100 });
  const result = { completed: 0, discarded: 0, irreversible: 0 };
  for (let index = 0; index < pending.edges.length; index += 1) {
    try {
      const outcome = await settlePendingMergeRecord(context, pending.edges[index].node);
      if (outcome !== 'settled') result[outcome] += 1;
    } catch (error: any) {
      // Its merge still runs and holds the participants: the record is settled at a later cycle.
      if (error.name !== TYPE_LOCK_ERROR) throw error;
    }
  }
  return result;
};

/**
 * Settle one pending record from the live graph (see completePendingMergeRecords). Also used by a retried acceptance,
 * which holds the proposal lock: a pending record is written before the merge starts, so it is no proof that it ran.
 * Settled under the locks its merge holds on the participants, from the record read again: a merge still running keeps
 * them, and a record its merge settled in the meantime is left as it is ('settled').
 */
export const settlePendingMergeRecord = async (
  context: AuthContext,
  pendingRecord: BasicStoreEntityMergeRecord,
): Promise<'completed' | 'discarded' | 'irreversible' | 'settled'> => {
  let lock;
  try {
    // The sources of a merge that just ended are among the latest deletions, which a lock refuses: they are only read here.
    lock = await lockResources([pendingRecord.merge_target_id, ...pendingRecord.merge_source_ids], { restoredIds: pendingRecord.merge_source_ids });
    const record = await storeLoadById<BasicStoreEntityMergeRecord>(context, SYSTEM_USER, pendingRecord.internal_id, ENTITY_TYPE_MERGE_RECORD);
    if (!record || record.merge_status !== MERGE_STATUS_PENDING) return 'settled';
    const existing = await internalFindByIds(context, SYSTEM_USER, record.merge_source_ids, { baseData: true, toMap: true }) as unknown as Record<string, BasicStoreObject>;
    const remainingSourceIds = record.merge_source_ids.filter((id) => existing[id]);
    if (remainingSourceIds.length === record.merge_source_ids.length && !record.merge_started_at) {
      await deleteElementById(context, SYSTEM_USER, record.internal_id, ENTITY_TYPE_MERGE_RECORD);
      return 'discarded';
    }
    const target = await storeLoadByIdWithRefs<StoreObject>(context, SYSTEM_USER, record.merge_target_id);
    if (!target || remainingSourceIds.length > 0) {
      await patchAttribute(context, SYSTEM_USER, record.internal_id, ENTITY_TYPE_MERGE_RECORD, {
        merge_status: MERGE_STATUS_IRREVERSIBLE,
        irreversible_reason: target ? IRREVERSIBLE_MERGE_INTERRUPTED : IRREVERSIBLE_MERGED_ENTITY_DELETED,
      });
      return 'irreversible';
    }
    const liveFileIds = new Set((target.x_opencti_files ?? []).map((file) => file.id));
    const sources = record.merge_snapshot.sources.map((source) => ({ ...source, moved_file_ids: source.moved_file_ids.filter((id) => liveFileIds.has(id)) }));
    const irreversibleReason = completedIrreversibleReason(record.irreversible_reason ?? null, record.merge_snapshot.sources, sources, target);
    await completeMergeRecord(context, record.internal_id, record.merge_snapshot.target, sources, target, irreversibleReason);
    return 'completed';
  } finally {
    if (lock) await lock.unlock();
  }
};
// endregion

// region queries
// The surviving entity and the sources: any of them that exists today (a source an unmerge restored included) can be
// reclassified after the merge.
const participantIdsOf = (record: BasicStoreEntityMergeRecord) => [record.merge_target_id, ...(record.merge_source_ids ?? [])].filter(isNotEmptyField);

export const findMergeRecordById = async (context: AuthContext, user: AuthUser, id: string) => {
  const record = await storeLoadById<BasicStoreEntityMergeRecord>(context, user, id, ENTITY_TYPE_MERGE_RECORD);
  if (!record) return record;
  const [readable] = await keepWithReadableParticipants(context, user, [record], participantIdsOf);
  return readable;
};

const sameIdSet = (left: string[], right: string[]) => left.length === right.length && left.every((id) => right.includes(id));

/**
 * Keep the restrictions of the merge records of these participants in line with them: the markings of the merge
 * (kept in the snapshot, or the record's own once the snapshot is dropped) plus the current markings of the
 * participants that exist, and the organizations every participant is shared with, at the merge and now. Run when a participant
 * is reclassified and after an unmerge, so the platform filters and counts merge records like any other element.
 */
export const refreshMergeRecordRestrictions = async (context: AuthContext, participantIds: string[], opts: { locks?: string[] } = {}) => {
  if (participantIds.length === 0) return 0;
  const records = await fullEntitiesList<BasicStoreEntityMergeRecord>(context, SYSTEM_USER, [ENTITY_TYPE_MERGE_RECORD], {
    filters: {
      mode: FilterMode.Or,
      filters: [
        { key: ['merge_target_id'], values: participantIds, operator: FilterOperator.Eq },
        { key: ['merge_source_ids'], values: participantIds, operator: FilterOperator.Eq },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  if (records.length === 0) return 0;
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  let refreshed = 0;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    const existing = await internalFindByIds(context, SYSTEM_USER, participantIdsOf(record), { baseData: true }) as BasicStoreBase[];
    // Without any participant left, the restrictions of the merge are all that protect the record.
    if (existing.length === 0) continue;
    const current = computeSubjectRestrictions(existing, settings?.platform_organization);
    const snapshot = record.merge_snapshot;
    const snapshotParticipants = snapshot ? [snapshot.target, ...snapshot.sources] : [];
    const mergeMarkings = snapshot
      ? snapshotParticipants.flatMap((participant) => (participant.refs?.[INPUT_MARKINGS] as string[] | undefined) ?? [])
      : ((record as Record<string, any>)[RELATION_OBJECT_MARKING] ?? []) as string[];
    const markingIds = R.uniq([...mergeMarkings, ...current.markingIds]);
    // The merged entity carries the organizations of every participant: the organizations of the merge (the snapshot,
    // or the record's own once the snapshot is dropped) keep the record from widening to them.
    const mergeOrganizationSets = snapshot
      ? snapshotParticipants.map((participant) => (participant.refs?.[INPUT_GRANTED_REFS] as string[] | undefined) ?? [])
      : [((record as Record<string, any>)[RELATION_GRANTED_TO] ?? []) as string[]];
    const currentOrganizationSets = existing.map((participant) => ((participant as Record<string, any>)[RELATION_GRANTED_TO] ?? []) as string[]);
    const organizationIds = intersectGrantedOrganizations([...mergeOrganizationSets, ...currentOrganizationSets], settings?.platform_organization);
    const inputs: EditInput[] = [];
    if (!sameIdSet(markingIds, ((record as Record<string, any>)[RELATION_OBJECT_MARKING] ?? []) as string[])) {
      inputs.push({ key: INPUT_MARKINGS, value: markingIds, operation: EditOperation.Replace });
    }
    // Organization sharing is an Enterprise Edition capability: without it, the platform neither applies nor accepts it.
    if (isEnterpriseEditionFromSettings(settings) && !sameIdSet(organizationIds, ((record as Record<string, any>)[RELATION_GRANTED_TO] ?? []) as string[])) {
      inputs.push({ key: INPUT_GRANTED_REFS, value: organizationIds, operation: EditOperation.Replace });
    }
    if (inputs.length === 0) continue;
    await updateAttribute(context, SYSTEM_USER, record.internal_id, ENTITY_TYPE_MERGE_RECORD, inputs, { locks: opts.locks ?? [] });
    refreshed += 1;
  }
  return refreshed;
};

// The records follow the restrictions of their participants (refreshMergeRecordRestrictions), so the platform filters
// and counts them; the participant check guards the moments before a refresh.
export const findMergeRecordsPaginated = async (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityMergeRecord>) => {
  return pageWithReadableParticipants<BasicStoreEntityMergeRecord>(context, user, ENTITY_TYPE_MERGE_RECORD, opts, participantIdsOf);
};

const hasInterruptedUnmerge = (record: BasicStoreEntityMergeRecord) => (record.unmerge_pending_source_ids ?? []).length > 0;

export const isMergeRecordReversible = (record: BasicStoreEntityMergeRecord) => {
  // An interrupted unmerge can always be completed: the graph is half restored.
  if (hasInterruptedUnmerge(record)) return true;
  const isOpen = record.merge_status === MERGE_STATUS_ACTIVE || record.merge_status === MERGE_STATUS_PARTIALLY_REVERTED;
  return isOpen && !record.irreversible_reason && new Date(record.reversible_until).getTime() >= Date.now();
};
// endregion

// region unmerge
const filterExistingRefs = async (context: AuthContext, refs: MergeSnapshotRef): Promise<MergeSnapshotRef> => {
  const ids = R.uniq(Object.values(refs).flatMap((value) => (Array.isArray(value) ? value : [value])).filter((id): id is string => typeof id === 'string'));
  if (ids.length === 0) return {};
  const existing = await internalFindByIds(context, SYSTEM_USER, ids, { baseData: true, toMap: true }) as unknown as Record<string, BasicStoreObject>;
  const filtered: MergeSnapshotRef = {};
  Object.entries(refs).forEach(([name, value]) => {
    if (Array.isArray(value)) {
      const kept = value.filter((id) => existing[id]);
      if (kept.length > 0) filtered[name] = kept;
    } else if (typeof value === 'string' && existing[value]) {
      filtered[name] = value;
    }
  });
  return filtered;
};

const describeAttributeFor = (entityType: string) => (key: string) => {
  const attribute = schemaAttributesDefinition.getAttribute(entityType, key);
  return attribute ? { multiple: isMultipleAttribute(entityType, key) } : undefined;
};

/**
 * A file that cannot be copied back stops the unmerge, after the references of the files already moved are written:
 * the sources stay pending, and resuming the unmerge copies that file again instead of leaving it on the target.
 */
export const moveFilesBack = async (
  context: AuthContext,
  user: AuthUser,
  target: StoreObject,
  restored: StoreObject,
  movedFileIds: string[],
  locks: string[],
) => {
  if (movedFileIds.length === 0) return;
  const restoredFiles = [];
  const movedSet = new Set<string>();
  let failedFileId: string | null = null;
  for (let index = 0; index < movedFileIds.length; index += 1) {
    const fileId = movedFileIds[index];
    const restoredId = fileId.replace(entityFilesPath(target), entityFilesPath(restored));
    const document = await loadFile(context, SYSTEM_USER, fileId, { dontThrow: true });
    if (!document) {
      // Already moved back by an interrupted unmerge: only the references are missing.
      const alreadyRestored = await loadFile(context, SYSTEM_USER, restoredId, { dontThrow: true });
      if (alreadyRestored) {
        restoredFiles.push(storeFileConverter(user, alreadyRestored as any));
        movedSet.add(fileId);
      } else {
        logApp.warn('[CURATION] Merged file not found anymore, it cannot be moved back', { fileId });
      }
      continue;
    }
    const copied = await copyFile(context, { sourceId: fileId, targetId: restoredId, sourceDocument: document as any, targetEntityId: restored.internal_id });
    if (!copied) {
      failedFileId = fileId;
      break;
    }
    restoredFiles.push(storeFileConverter(user, copied));
    await deleteFile(context, SYSTEM_USER, fileId);
    movedSet.add(fileId);
  }
  if (restoredFiles.length > 0) {
    const restoredFileIds = new Set(restoredFiles.map((file) => file.id));
    const keptOnRestored = (restored.x_opencti_files ?? []).filter((file) => !restoredFileIds.has(file.id));
    await patchAttribute(context, SYSTEM_USER, restored.internal_id, restored.entity_type, { x_opencti_files: [...keptOnRestored, ...restoredFiles] }, { locks });
    const remaining = (target.x_opencti_files ?? []).filter((file) => !movedSet.has(file.id));
    await patchAttribute(context, SYSTEM_USER, target.internal_id, target.entity_type, { x_opencti_files: remaining }, { locks });
  }
  if (failedFileId) {
    throw DatabaseError('A merged file cannot be moved back to the restored entity: undo the merge again to resume the unmerge', { file_id: failedFileId });
  }
};

const hasRelationshipBetween = async (context: AuthContext, relationshipType: string, fromId: string, toId: string) => {
  const existing = await fullRelationsList(context, SYSTEM_USER, relationshipType, { fromId, toId, baseData: true });
  return existing.length > 0;
};

const addMoved = (moved: Map<string, MergeRedirectedRelationship[]>, sourceId: string, relationship: MergeRedirectedRelationship) => {
  moved.set(sourceId, [...(moved.get(sourceId) ?? []), relationship]);
};

const recreateRelationship = async (context: AuthContext, user: AuthUser, relationship: MergeRecreatableRelationship, locks: string[]) => {
  const [alreadyRecreated] = await internalFindByIds(context, SYSTEM_USER, [relationship.id], { baseData: true }) as BasicStoreObject[];
  if (alreadyRecreated) {
    return alreadyRecreated;
  }
  const refs = await filterExistingRefs(context, relationship.refs);
  const relationInput = {
    ...relationship.attributes,
    ...refs,
    internal_id: relationship.id,
    standard_id: relationship.standard_id,
    relationship_type: relationship.entity_type,
    fromId: relationship.from_id,
    toId: relationship.to_id,
  };
  return createRelation(context, user, relationInput, { restore: true, locks });
};

export interface UnmergeResult {
  record: BasicStoreEntityMergeRecord;
  restored_ids: string[];
  repointed_count: number;
  recreated_count: number;
  skipped_relationship_ids: string[];
}

const loadReversibleRecord = async (context: AuthContext, user: AuthUser, mergeRecordId: string) => {
  const record = await findMergeRecordById(context, user, mergeRecordId);
  if (!record) {
    throw FunctionalError('Merge record not found', { id: mergeRecordId });
  }
  if (!isMergeRecordReversible(record)) {
    throw FunctionalError('This merge can no longer be reverted', {
      id: mergeRecordId,
      status: record.merge_status,
      reason: record.irreversible_reason ?? IRREVERSIBLE_RETENTION_OVER,
    });
  }
  return record;
};

/**
 * The identifiers of every source still to restore are held for the whole unmerge: they are freed on the merged entity
 * before each source is recreated, and a concurrent creation must not take them in between. These are the identifiers
 * a creation of the source would lock, its alias and hash identifiers included, so a creation named after one of its
 * aliases waits too. Sources are only ever marked restored, so the ones selected under the lock are among these.
 */
export const unmergeLockIds = (record: Pick<BasicStoreEntityMergeRecord, 'internal_id' | 'merge_target_id' | 'merge_snapshot'>) => {
  const sourceLockIds = record.merge_snapshot.sources
    .filter((source) => !source.reverted_at)
    .flatMap((source) => [
      ...getInputIds(source.entity_type, { ...source.attributes, entity_type: source.entity_type, internal_id: source.internal_id, standard_id: source.standard_id }),
      ...(source.contributed_stix_ids ?? []),
    ]);
  return R.uniq([record.internal_id, record.merge_target_id, ...sourceLockIds].filter(Boolean));
};

export const selectRevertedSources = (record: BasicStoreEntityMergeRecord, sourceIds?: string[] | null) => {
  const pendingSources = record.merge_snapshot.sources.filter((source) => !source.reverted_at);
  const requested = sourceIds && sourceIds.length > 0 ? R.uniq(sourceIds) : null;
  // A selection is restored as requested or not at all: an id that names no merged entity still to restore (unknown,
  // already restored) is a stale selection, never silently dropped while the others are restored.
  const unknownIds = requested ? requested.filter((id) => !pendingSources.some((source) => source.internal_id === id)) : [];
  if (unknownIds.length > 0) {
    throw FunctionalError('Some selected entities are not waiting to be restored by this merge (unknown or already restored): refresh the merge record and select again', {
      id: record.internal_id,
      source_ids: unknownIds,
    });
  }
  if (hasInterruptedUnmerge(record)) {
    // An interrupted unmerge is resumed exactly as it started.
    const interrupted = record.unmerge_pending_source_ids ?? [];
    if (requested && (requested.length !== interrupted.length || requested.some((id) => !interrupted.includes(id)))) {
      throw FunctionalError('An interrupted unmerge of this merge must be completed first', { id: record.internal_id, pending_source_ids: interrupted });
    }
    return pendingSources.filter((source) => interrupted.includes(source.internal_id));
  }
  return requested ? pendingSources.filter((source) => requested.includes(source.internal_id)) : pendingSources;
};

/**
 * Revert a recorded merge, entirely or for some of its sources: the merged-away entities are recreated with their
 * original identifiers, attributes and references, the relationships they carried are re-pointed back (or recreated
 * when the merge had dropped them as duplicates), and what they brought to the target is removed from it.
 * The reverted sources are written on the record before the first change: an unmerge that fails half way is resumed
 * by the next call, every step skipping what was already restored.
 */
export const unmergeFromRecord = async (context: AuthContext, user: AuthUser, mergeRecordId: string, sourceIds?: string[] | null): Promise<UnmergeResult> => {
  const initialRecord = await loadReversibleRecord(context, user, mergeRecordId);
  const lockIds = unmergeLockIds(initialRecord);
  // A merge lists its sources among the deletions of the last seconds, which a lock refuses: the sources still to restore
  // are tolerated by this lock, and each restoration clears its entry while the lock is held.
  const pendingSourceIds = initialRecord.merge_snapshot.sources.filter((source) => !source.reverted_at).map((source) => source.internal_id);
  let lock;
  try {
    lock = await lockResources(lockIds, { restoredIds: pendingSourceIds });
    // Read again under the lock: a concurrent unmerge may have changed the record.
    const record = await loadReversibleRecord(context, user, mergeRecordId);
    const snapshot = record.merge_snapshot;
    const reverting = selectRevertedSources(record, sourceIds);
    if (reverting.length === 0) {
      throw FunctionalError('No merged entity left to restore for this merge record', { id: mergeRecordId, sourceIds });
    }
    const remaining = snapshot.sources.filter((source) => !source.reverted_at && !reverting.includes(source));
    const target = await storeLoadByIdWithRefs<StoreObject>(context, user, record.merge_target_id);
    if (!target) {
      throw FunctionalError('The entity the merge produced does not exist anymore (deleted or merged again). Revert its most recent merge first.', {
        id: mergeRecordId,
        target_id: record.merge_target_id,
      });
    }
    controlUserConfidenceAgainstElement(user, target);
    if (!hasInterruptedUnmerge(record)) {
      await patchAttribute(context, SYSTEM_USER, record.internal_id, ENTITY_TYPE_MERGE_RECORD, {
        unmerge_pending_source_ids: reverting.map((source) => source.internal_id),
      }, { locks: lockIds });
    }
    // 1. Remove from the target what the reverted sources brought (identifiers first, to free them for the restore).
    // Only values still on the target are removed, so a resumed unmerge removes nothing twice.
    const revertInputs = computeTargetRevertInputs(
      snapshot.target,
      { attributes: snapshotAttributes(target), refs: snapshotRefs(target) },
      reverting,
      remaining,
      describeAttributeFor(target.entity_type),
      schemaRelationsRefDefinition.getRelationsRef(target.entity_type).map((ref) => ({ name: ref.name, multiple: ref.multiple })),
    );
    if (revertInputs.length > 0) {
      await updateAttribute(context, user, target.internal_id, target.entity_type, revertInputs as any, { locks: lockIds });
    }
    // 2. Recreate the merged-away entities and give them back the relationships the merge moved to the target.
    const restoredIds: string[] = [];
    let repointedCount = 0;
    let recreatedCount = 0;
    const skippedRelationshipIds: string[] = [];
    for (let index = 0; index < reverting.length; index += 1) {
      const source = reverting[index];
      const refs = await filterExistingRefs(context, source.refs);
      const restoreInput = {
        ...source.attributes,
        ...refs,
        internal_id: source.internal_id,
        standard_id: source.standard_id,
      };
      const [alreadyRestored] = await internalFindByIds(context, SYSTEM_USER, [source.internal_id]) as unknown as StoreObject[];
      const restored = alreadyRestored?.entity_type === source.entity_type
        ? alreadyRestored
        : await restoreEntityFromMergeSnapshot(context, user, restoreInput, source.entity_type, { locks: lockIds });
      restoredIds.push(restored.internal_id);
      const restoredLoaded = await storeLoadByIdWithRefs<StoreObject>(context, SYSTEM_USER, restored.internal_id);
      const liveTarget = await storeLoadByIdWithRefs<StoreObject>(context, SYSTEM_USER, target.internal_id);
      if (restoredLoaded && liveTarget) {
        await moveFilesBack(context, user, liveTarget, restoredLoaded, source.moved_file_ids, lockIds);
      }
      const { repointed, skipped } = await repointRelationships(context, user, source.redirected.map((relation) => ({
        relationId: relation.id,
        side: relation.side,
        previousEntityId: target.internal_id,
        newEntity: {
          internal_id: restored.internal_id,
          entity_type: restored.entity_type,
          name: nameOf(restored) ?? source.name,
          _index: restoredLoaded?._index ?? restored._index,
        },
      })));
      repointedCount += repointed.length;
      skippedRelationshipIds.push(...skipped);
    }
    // 3. Recreate the relationships the merge removed, once every reverted source exists again: one between two sources is
    // listed by both and recreated once. One whose other side stays merged is recreated against the target, which that
    // side is part of, and moves to the redirected relationships of the source still merged, whose own unmerge points it
    // back. When the target already holds an equivalent, it stays listed by that source instead, whose unmerge recreates it.
    const remainingIds = new Set(remaining.map((source) => source.internal_id));
    const movedToTarget = new Map<string, MergeRedirectedRelationship[]>();
    const recreatables = R.uniqBy((relationship) => relationship.id, reverting.flatMap((source) => source.recreatable));
    for (let relationIndex = 0; relationIndex < recreatables.length; relationIndex += 1) {
      const relationship = recreatables[relationIndex];
      const fromStaysMerged = remainingIds.has(relationship.from_id);
      const toStaysMerged = remainingIds.has(relationship.to_id);
      const fromId = fromStaysMerged ? target.internal_id : relationship.from_id;
      const toId = toStaysMerged ? target.internal_id : relationship.to_id;
      try {
        if (fromStaysMerged || toStaysMerged) {
          const [alreadyRecreated] = await internalFindByIds(context, SYSTEM_USER, [relationship.id], { baseData: true }) as BasicStoreObject[];
          if (!alreadyRecreated && await hasRelationshipBetween(context, relationship.entity_type, fromId, toId)) continue;
        }
        await recreateRelationship(context, user, { ...relationship, from_id: fromId, to_id: toId }, lockIds);
        recreatedCount += 1;
        if (fromStaysMerged) {
          addMoved(movedToTarget, relationship.from_id, { id: relationship.id, entity_type: relationship.entity_type, side: 'from', other_id: relationship.to_id, other_type: relationship.to_type });
        }
        if (toStaysMerged) {
          addMoved(movedToTarget, relationship.to_id, { id: relationship.id, entity_type: relationship.entity_type, side: 'to', other_id: relationship.from_id, other_type: relationship.from_type });
        }
      } catch (err) {
        // A transient failure stops the unmerge before the sources are marked reverted: their pending state is kept and
        // resuming it recreates this relationship again.
        if (!isIrrecoverableRecreationError(err)) throw err;
        skippedRelationshipIds.push(relationship.id);
        logApp.warn('[CURATION] Relationship removed by the merge cannot be recreated', { cause: err, relationship_id: relationship.id, merge_record_id: mergeRecordId });
      }
    }
    // 4. Close the record (or the reverted part of it).
    const revertedAt = now();
    const revertedIds = new Set(reverting.map((source) => source.internal_id));
    const updatedSnapshot: MergeSnapshot = {
      ...snapshot,
      sources: snapshot.sources.map((source) => {
        if (revertedIds.has(source.internal_id)) return { ...source, reverted_at: revertedAt };
        const moved = movedToTarget.get(source.internal_id) ?? [];
        if (moved.length === 0) return source;
        const movedIds = new Set(moved.map((relationship) => relationship.id));
        return {
          ...source,
          redirected: [...source.redirected.filter((relationship) => !movedIds.has(relationship.id)), ...moved],
          recreatable: source.recreatable.filter((relationship) => !movedIds.has(relationship.id)),
        };
      }),
    };
    const status = remaining.length === 0 ? MERGE_STATUS_REVERTED : MERGE_STATUS_PARTIALLY_REVERTED;
    // The proposal stays applied while sources remain merged: reverting it later undoes the rest of the merge. It is
    // closed before the record, which keeps its recovery marker until then: if either write fails, the unmerge is
    // resumed from the record and closes both.
    if (record.proposal_id && status === MERGE_STATUS_REVERTED) {
      await markProposalReverted(context, record.proposal_id);
    }
    const { element: updatedElement } = await patchAttribute(context, SYSTEM_USER, record.internal_id, ENTITY_TYPE_MERGE_RECORD, {
      merge_snapshot: updatedSnapshot,
      merge_status: status,
      unmerged_at: revertedAt,
      unmerged_by_id: user.id,
      unmerge_pending_source_ids: [],
    }, { locks: lockIds });
    const updatedRecord = updatedElement as unknown as BasicStoreEntityMergeRecord;
    // The restored sources are participants again: the record takes their restrictions.
    await refreshMergeRecordRestrictions(context, [target.internal_id], { locks: lockIds });
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'extended',
      message: `unmerges \`${reverting.map((source) => source.name).join(', ')}\` from \`${nameOf(target) ?? target.standard_id}\``,
      context_data: {
        id: target.internal_id,
        entity_type: target.entity_type,
        input: { merge_record_id: record.internal_id, restored_ids: restoredIds, repointed: repointedCount, recreated: recreatedCount },
      },
    });
    await addCurationUnmergeCount();
    const finalTarget = await storeLoadById(context, user, target.internal_id, ABSTRACT_STIX_CORE_OBJECT);
    if (finalTarget) {
      await notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, finalTarget, user);
    }
    return { record: updatedRecord, restored_ids: restoredIds, repointed_count: repointedCount, recreated_count: recreatedCount, skipped_relationship_ids: skippedRelationshipIds };
  } catch (err: any) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: lockIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

/**
 * Close one merge record past its retention window, under the lock an unmerge holds on the record and from the record
 * read again: an unmerge that ended in the meantime may have reverted it. Returns false when it stays open.
 */
const expireMergeRecord = async (context: AuthContext, recordId: string) => {
  let lock;
  try {
    lock = await lockResources([recordId]);
    const record = await storeLoadById<BasicStoreEntityMergeRecord>(context, SYSTEM_USER, recordId, ENTITY_TYPE_MERGE_RECORD);
    const isOpen = record?.merge_status === MERGE_STATUS_ACTIVE || record?.merge_status === MERGE_STATUS_PARTIALLY_REVERTED;
    // A record with an interrupted unmerge keeps its snapshot until the unmerge is completed.
    if (!record || !isOpen || hasInterruptedUnmerge(record)) return false;
    // The markings and organization sharing of each participant stay: the record keeps the restrictions of the merge
    // when it is refreshed after its retention window, and never widens to the survivor's alone.
    const accessRefs = (refs: MergeSnapshotRef | undefined): MergeSnapshotRef => R.pick([INPUT_MARKINGS, INPUT_GRANTED_REFS], refs ?? {});
    const lightSnapshot: MergeSnapshot = {
      target: { ...record.merge_snapshot.target, attributes: {}, post_attributes: {}, refs: accessRefs(record.merge_snapshot.target.refs), post_refs: {} },
      sources: record.merge_snapshot.sources.map((source) => ({ ...source, attributes: {}, refs: accessRefs(source.refs), redirected: [], recreatable: [] })),
    };
    await patchAttribute(context, SYSTEM_USER, record.internal_id, ENTITY_TYPE_MERGE_RECORD, {
      merge_status: MERGE_STATUS_IRREVERSIBLE,
      irreversible_reason: IRREVERSIBLE_RETENTION_OVER,
      merge_snapshot: lightSnapshot,
    }, { locks: [record.internal_id] });
    return true;
  } catch (error: any) {
    // An unmerge still running holds the record: it is closed at a later run.
    if (error.name === TYPE_LOCK_ERROR) return false;
    throw error;
  } finally {
    if (lock) await lock.unlock();
  }
};

/**
 * Close the merge records whose retention window is over: they become irreversible and their heavy snapshot part
 * (relationships) is dropped to free storage, the participants and alias provenance stay for the history.
 */
export const expireMergeRecords = async (context: AuthContext) => {
  const filters = {
    mode: 'and' as const,
    filters: [
      { key: ['merge_status'], values: [MERGE_STATUS_ACTIVE, MERGE_STATUS_PARTIALLY_REVERTED] },
      { key: ['reversible_until'], values: [new Date().toISOString()], operator: 'lt' as const },
    ],
    filterGroups: [],
  };
  // Pages are read in a stable order until the last one, so records skipped below never hold back the ones after them.
  let expiredCount = 0;
  let after: string | undefined;
  do {
    const page = await pageEntitiesConnection<BasicStoreEntityMergeRecord>(context, SYSTEM_USER, [ENTITY_TYPE_MERGE_RECORD], {
      filters: filters as any,
      first: EXPIRY_PAGE_SIZE,
      after,
      orderBy: 'reversible_until',
      orderMode: 'asc',
    } as any);
    const records = page.edges.map((edge) => edge.node).filter((record) => !hasInterruptedUnmerge(record));
    for (let index = 0; index < records.length; index += 1) {
      if (await expireMergeRecord(context, records[index].internal_id)) expiredCount += 1;
    }
    after = page.pageInfo.hasNextPage ? (page.pageInfo.endCursor ?? undefined) : undefined;
  } while (after);
  return expiredCount;
};
// endregion
