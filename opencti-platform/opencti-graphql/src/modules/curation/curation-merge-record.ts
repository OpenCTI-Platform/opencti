import * as R from 'ramda';
import conf, { BUS_TOPICS, booleanConf, logApp } from '../../config/conf';
import { FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
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
import { internalFindByIds, pageEntitiesConnection, storeLoadById, type EntityOptions } from '../../database/middleware-loader';
import { lockResources } from '../../lock/master-lock';
import { getDraftContext } from '../../utils/draftContext';
import { SYSTEM_USER } from '../../utils/access';
import { controlUserConfidenceAgainstElement } from '../../utils/confidence-level';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { isInferredIndex, isNotEmptyField } from '../../database/utils';
import { schemaAttributesDefinition, isMultipleAttribute } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { isStixRefRelationship } from '../../schema/stixRefRelationship';
import { ABSTRACT_STIX_CORE_OBJECT, INPUT_MARKINGS } from '../../schema/general';
import { copyFile, deleteFile, loadFile, storeFileConverter } from '../../database/file-storage';
import { addCurationMergeRecordCount, addCurationUnmergeCount } from '../../manager/telemetryManager';
import { now } from '../../utils/format';
import {
  type AliasProvenance,
  type BasicStoreEntityMergeRecord,
  ENTITY_TYPE_CURATION_PROPOSAL,
  ENTITY_TYPE_MERGE_RECORD,
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
  PROPOSAL_STATUS_REVERTED,
} from './curation-types';
import { computeTargetRevertInputs, isIrrecoverableRecreationError, isSnapshotAttribute } from './curation-merge-diff';
import { getCurationSettings } from './curation-settings';

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
  const redirectedIds = new Set([...plan.fromRedirects, ...plan.toRedirects].map((dependency) => dependency.i_relation.internal_id));
  let irreversibleReason: string | null = null;
  const sourceSnapshots: MergeSourceSnapshot[] = [];
  const recreatableIdsBySource = new Map<string, string[]>();
  const targetAliasKeys = new Set([nameOf(target), ...aliasesOf(target)].filter((v): v is string => typeof v === 'string' && v.length > 0).map((v) => v.toLowerCase()));
  const targetStixIds = new Set([target.standard_id, ...(target.x_opencti_stix_ids ?? [])]);
  sources.forEach((source) => {
    const redirected: MergeRedirectedRelationship[] = [];
    plan.fromRedirects.forEach(({ i_relation: relation }) => {
      if (relation.fromId === source.internal_id && !isStixRefRelationship(relation.entity_type) && !isInferredIndex(relation._index)) {
        redirected.push({ id: relation.internal_id, entity_type: relation.entity_type, side: 'from', other_id: relation.toId, other_type: relation.toType });
      }
    });
    plan.toRedirects.forEach(({ i_relation: relation }) => {
      if (relation.toId === source.internal_id && !isInferredIndex(relation._index)) {
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
    ].filter((relation) => !redirectedIds.has(relation.internal_id) && !isInferredIndex(relation._index)).map((relation) => relation.internal_id));
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
  const allRecreatableIds = [...recreatableIdsBySource.values()].flat();
  if (allRecreatableIds.length > MAX_RECREATABLE_RELATIONSHIPS) {
    irreversibleReason = `The merge removed ${allRecreatableIds.length} duplicated relationships, above the snapshot limit of ${MAX_RECREATABLE_RELATIONSHIPS}`;
  } else if (totalRedirected > MAX_REDIRECTED_RELATIONSHIPS) {
    irreversibleReason = `The merge moved ${totalRedirected} relationships, above the snapshot limit of ${MAX_REDIRECTED_RELATIONSHIPS}`;
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
  // The merged entity ends up with the markings and the organizations of every participant: the record, which holds
  // a copy of each of them, gets the same restrictions.
  const participants = [targetSnapshot, ...sourceSnapshots];
  const refIdsOf = (refs: MergeSnapshotRef, name: string) => (refs[name] as string[] | undefined) ?? [];
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
    relationships_recreatable_count: sourceSnapshots.reduce((acc, s) => acc + s.recreatable.length, 0),
    merged_by_id: user.id,
    proposal_id: metadata?.proposal_id ?? null,
    objectMarking: R.uniq(participants.flatMap((participant) => refIdsOf(participant.refs, INPUT_MARKINGS))),
    objectOrganization: R.uniq(participants.flatMap((participant) => refIdsOf(participant.refs, 'objectOrganization'))),
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
    merge_snapshot: snapshot,
  });
  await addCurationMergeRecordCount();
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
  await completeMergeRecord(context, preparation.recordId, preparation.target, sourceSnapshots, mergedInstance, preparation.irreversibleReason);
};

const abortMergeRecord = async (context: AuthContext, preparation: MergeRecordPreparation | null) => {
  if (!preparation) {
    return;
  }
  await deleteElementById(context, SYSTEM_USER, preparation.recordId, ENTITY_TYPE_MERGE_RECORD);
};

export const curationMergeRecorder: MergeRecorder<MergeRecordPreparation | null> = {
  isEnabled: () => MERGE_RECORDS_ENABLED,
  prepare: prepareMergeRecord,
  commit: commitMergeRecord,
  abort: abortMergeRecord,
};

const PENDING_RECORD_GRACE_MS = 10 * 60 * 1000;

/**
 * Complete the records left pending by a merge whose completion step failed (or by a stopped platform), from the
 * live graph: merged sources are gone, so the merge ran and the record becomes active; sources still all there mean
 * the merge never ran and the record is discarded; a partial state cannot be reverted safely.
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
    const record = pending.edges[index].node;
    const existing = await internalFindByIds(context, SYSTEM_USER, record.merge_source_ids, { baseData: true, toMap: true }) as unknown as Record<string, BasicStoreObject>;
    const remainingSourceIds = record.merge_source_ids.filter((id) => existing[id]);
    if (remainingSourceIds.length === record.merge_source_ids.length) {
      await deleteElementById(context, SYSTEM_USER, record.internal_id, ENTITY_TYPE_MERGE_RECORD);
      result.discarded += 1;
      continue;
    }
    const target = await storeLoadByIdWithRefs<StoreObject>(context, SYSTEM_USER, record.merge_target_id);
    if (!target || remainingSourceIds.length > 0) {
      await patchAttribute(context, SYSTEM_USER, record.internal_id, ENTITY_TYPE_MERGE_RECORD, {
        merge_status: MERGE_STATUS_IRREVERSIBLE,
        irreversible_reason: target ? 'The merge was interrupted before all the entities were merged' : 'The merged entity was deleted before the merge record was completed',
      });
      result.irreversible += 1;
      continue;
    }
    const liveFileIds = new Set((target.x_opencti_files ?? []).map((file) => file.id));
    const sources = record.merge_snapshot.sources.map((source) => ({ ...source, moved_file_ids: source.moved_file_ids.filter((id) => liveFileIds.has(id)) }));
    await completeMergeRecord(context, record.internal_id, record.merge_snapshot.target, sources, target, record.irreversible_reason ?? null);
    result.completed += 1;
  }
  return result;
};
// endregion

// region queries
/**
 * A record carries the restrictions its participants had at merge time, and the surviving entity can be
 * reclassified afterwards: a record is shown only to users who can still read that entity. A record whose entity
 * no longer exists (deleted, or merged away later) keeps its own restrictions only.
 */
const withReadableTargets = async (context: AuthContext, user: AuthUser, records: BasicStoreEntityMergeRecord[]) => {
  const targetIds = R.uniq(records.map((record) => record.merge_target_id).filter(isNotEmptyField));
  if (targetIds.length === 0) return records;
  const readable = await internalFindByIds(context, user, targetIds, { baseData: true }) as BasicStoreBase[];
  const readableIds = new Set(readable.map((element) => element.internal_id));
  const unreadableIds = targetIds.filter((id) => !readableIds.has(id));
  if (unreadableIds.length === 0) return records;
  const existing = await internalFindByIds(context, SYSTEM_USER, unreadableIds, { baseData: true }) as BasicStoreBase[];
  const hiddenIds = new Set(existing.map((element) => element.internal_id));
  return records.filter((record) => !hiddenIds.has(record.merge_target_id));
};

export const findMergeRecordById = async (context: AuthContext, user: AuthUser, id: string) => {
  const record = await storeLoadById<BasicStoreEntityMergeRecord>(context, user, id, ENTITY_TYPE_MERGE_RECORD);
  if (!record) return record;
  const [readable] = await withReadableTargets(context, user, [record]);
  return readable;
};

export const findMergeRecordsPaginated = async (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityMergeRecord>) => {
  const connection = await pageEntitiesConnection<BasicStoreEntityMergeRecord>(context, user, [ENTITY_TYPE_MERGE_RECORD], opts);
  const readable = new Set(await withReadableTargets(context, user, connection.edges.map((edge) => edge.node)));
  return { ...connection, edges: connection.edges.filter((edge) => readable.has(edge.node)) };
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

const moveFilesBack = async (
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
    if (copied) {
      restoredFiles.push(storeFileConverter(user, copied));
      await deleteFile(context, SYSTEM_USER, fileId);
      movedSet.add(fileId);
    }
  }
  if (restoredFiles.length > 0) {
    const restoredFileIds = new Set(restoredFiles.map((file) => file.id));
    const keptOnRestored = (restored.x_opencti_files ?? []).filter((file) => !restoredFileIds.has(file.id));
    await patchAttribute(context, SYSTEM_USER, restored.internal_id, restored.entity_type, { x_opencti_files: [...keptOnRestored, ...restoredFiles] });
    const remaining = (target.x_opencti_files ?? []).filter((file) => !movedSet.has(file.id));
    await patchAttribute(context, SYSTEM_USER, target.internal_id, target.entity_type, { x_opencti_files: remaining }, { locks });
  }
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
      reason: record.irreversible_reason ?? 'retention window expired',
    });
  }
  return record;
};

const selectRevertedSources = (record: BasicStoreEntityMergeRecord, sourceIds?: string[] | null) => {
  const pendingSources = record.merge_snapshot.sources.filter((source) => !source.reverted_at);
  const requested = sourceIds && sourceIds.length > 0 ? sourceIds : null;
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
  const lockIds = [mergeRecordId, initialRecord.merge_target_id];
  let lock;
  try {
    lock = await lockResources(lockIds);
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
    // 2. Recreate the merged-away entities and give them back their relationships.
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
        : await restoreEntityFromMergeSnapshot(context, user, restoreInput, source.entity_type);
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
      for (let relationIndex = 0; relationIndex < source.recreatable.length; relationIndex += 1) {
        const relationship = source.recreatable[relationIndex];
        try {
          await recreateRelationship(context, user, relationship, lockIds);
          recreatedCount += 1;
        } catch (err) {
          // A transient failure stops the unmerge before the source is marked reverted: its pending state is kept and
          // resuming it recreates this relationship again.
          if (!isIrrecoverableRecreationError(err)) throw err;
          skippedRelationshipIds.push(relationship.id);
          logApp.warn('[CURATION] Relationship removed by the merge cannot be recreated', { cause: err, relationship_id: relationship.id, merge_record_id: mergeRecordId });
        }
      }
    }
    // 3. Close the record (or the reverted part of it).
    const revertedAt = now();
    const revertedIds = new Set(reverting.map((source) => source.internal_id));
    const updatedSnapshot: MergeSnapshot = {
      ...snapshot,
      sources: snapshot.sources.map((source) => (revertedIds.has(source.internal_id) ? { ...source, reverted_at: revertedAt } : source)),
    };
    const status = remaining.length === 0 ? MERGE_STATUS_REVERTED : MERGE_STATUS_PARTIALLY_REVERTED;
    const { element: updatedElement } = await patchAttribute(context, SYSTEM_USER, record.internal_id, ENTITY_TYPE_MERGE_RECORD, {
      merge_snapshot: updatedSnapshot,
      merge_status: status,
      unmerged_at: revertedAt,
      unmerged_by_id: user.id,
      unmerge_pending_source_ids: [],
    }, { locks: lockIds });
    const updatedRecord = updatedElement as unknown as BasicStoreEntityMergeRecord;
    if (record.proposal_id) {
      await patchAttribute(context, SYSTEM_USER, record.proposal_id, ENTITY_TYPE_CURATION_PROPOSAL, { proposal_status: PROPOSAL_STATUS_REVERTED });
    }
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
    // A record with an interrupted unmerge keeps its snapshot until the unmerge is completed.
    const expired = page.edges.map((edge) => edge.node).filter((record) => !hasInterruptedUnmerge(record));
    for (let index = 0; index < expired.length; index += 1) {
      const record = expired[index];
      const lightSnapshot: MergeSnapshot = {
        target: { ...record.merge_snapshot.target, attributes: {}, post_attributes: {}, refs: {}, post_refs: {} },
        sources: record.merge_snapshot.sources.map((source) => ({ ...source, attributes: {}, refs: {}, redirected: [], recreatable: [] })),
      };
      await patchAttribute(context, SYSTEM_USER, record.internal_id, ENTITY_TYPE_MERGE_RECORD, {
        merge_status: MERGE_STATUS_IRREVERSIBLE,
        irreversible_reason: 'The retention window of this merge is over',
        merge_snapshot: lightSnapshot,
      });
    }
    expiredCount += expired.length;
    after = page.pageInfo.hasNextPage ? (page.pageInfo.endCursor ?? undefined) : undefined;
  } while (after);
  return expiredCount;
};
// endregion
