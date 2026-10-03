import * as R from 'ramda';
import conf, { BUS_TOPICS, booleanConf, logApp } from '../../config/conf';
import { FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreObject, StoreObject, StoreRelation } from '../../types/store';
import type { MergeCommitInput, MergePreparationInput, MergeRecorder } from '../../database/merge-hooks';
import {
  createEntity,
  createRelation,
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
  MERGE_STATUS_REVERTED,
  type MergeRecreatableRelationship,
  type MergeRedirectedRelationship,
  type MergeSnapshot,
  type MergeSnapshotRef,
  type MergeSourceSnapshot,
  type MergeTargetSnapshot,
  PROPOSAL_STATUS_REVERTED,
} from './curation-types';
import { computeTargetRevertInputs, isSnapshotAttribute } from './curation-merge-diff';
import { getCurationSettings } from './curation-settings';

const MERGE_RECORDS_ENABLED = booleanConf('curation:merge_records_enabled', true);
const MAX_RECREATABLE_RELATIONSHIPS = Number(conf.get('curation:merge_record_max_recreatable_relationships') ?? 10000);
const MAX_REDIRECTED_RELATIONSHIPS = Number(conf.get('curation:merge_record_max_redirected_relationships') ?? 100000);
const SNAPSHOT_LOAD_BATCH = 500;

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
  target: MergeTargetSnapshot;
  sources: MergeSourceSnapshot[];
  aliasProvenance: AliasProvenance[];
  irreversibleReason: string | null;
  metadata: Record<string, string>;
}

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
      moved_file_ids: [],
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
  return {
    target: {
      internal_id: target.internal_id,
      standard_id: target.standard_id,
      entity_type: target.entity_type,
      name: nameOf(target) ?? target.standard_id,
      attributes: snapshotAttributes(target),
      refs: snapshotRefs(target),
      post_attributes: {},
      post_refs: {},
      taken_from_source_id: sources[0]?.internal_id ?? null,
    },
    sources: sourceSnapshots,
    aliasProvenance,
    irreversibleReason,
    metadata: metadata ?? {},
  };
};

const commitMergeRecord = async (context: AuthContext, user: AuthUser, preparation: MergeRecordPreparation | null, input: MergeCommitInput) => {
  if (!preparation) {
    return;
  }
  const { mergedInstance, sources } = input;
  const settings = await getCurationSettings(context);
  const targetPathMarker = `/${mergedInstance.entity_type}/${mergedInstance.internal_id}/`;
  const sourcesById = new Map(sources.map((source) => [source.internal_id, source]));
  const sourceSnapshots = preparation.sources.map((snapshot) => {
    const mutated = sourcesById.get(snapshot.internal_id);
    const movedFileIds = (mutated?.x_opencti_files ?? []).map((file) => file.id).filter((id) => id.includes(targetPathMarker));
    return { ...snapshot, moved_file_ids: movedFileIds };
  });
  const snapshot: MergeSnapshot = {
    target: { ...preparation.target, post_attributes: snapshotAttributes(mergedInstance), post_refs: snapshotRefs(mergedInstance) },
    sources: sourceSnapshots,
  };
  const markingIds = R.uniq([
    ...((snapshot.target.post_refs[INPUT_MARKINGS] as string[] | undefined) ?? []),
    ...sourceSnapshots.flatMap((source) => (source.refs[INPUT_MARKINGS] as string[] | undefined) ?? []),
  ]);
  const organizationIds = (snapshot.target.post_refs.objectOrganization as string[] | undefined) ?? [];
  const reversibleUntil = new Date(Date.now() + settings.merge_record_retention_days * 24 * 3600 * 1000).toISOString();
  const record = {
    name: `${nameOf(mergedInstance) ?? mergedInstance.standard_id} <- ${sourceSnapshots.map((s) => s.name).join(', ')}`,
    merge_target_id: mergedInstance.internal_id,
    merge_target_type: mergedInstance.entity_type,
    merge_target_name: nameOf(mergedInstance) ?? mergedInstance.standard_id,
    merge_source_ids: sourceSnapshots.map((s) => s.internal_id),
    merge_source_names: sourceSnapshots.map((s) => s.name ?? s.standard_id),
    merge_status: preparation.irreversibleReason ? MERGE_STATUS_IRREVERSIBLE : MERGE_STATUS_ACTIVE,
    merge_snapshot: snapshot,
    alias_provenance: preparation.aliasProvenance,
    reversible_until: reversibleUntil,
    irreversible_reason: preparation.irreversibleReason,
    relationships_redirected_count: sourceSnapshots.reduce((acc, s) => acc + s.redirected.length, 0),
    relationships_recreatable_count: sourceSnapshots.reduce((acc, s) => acc + s.recreatable.length, 0),
    merged_by_id: user.id,
    proposal_id: preparation.metadata.proposal_id ?? null,
    objectMarking: markingIds,
    objectOrganization: organizationIds,
  };
  // Created by the system user: the record carries the restrictions of every merged element, which the merging
  // user may not be allowed to set (organization sharing), while merged_by_id keeps who merged.
  await createEntity(context, SYSTEM_USER, record, ENTITY_TYPE_MERGE_RECORD);
  await addCurationMergeRecordCount();
};

export const curationMergeRecorder: MergeRecorder<MergeRecordPreparation | null> = {
  isEnabled: () => MERGE_RECORDS_ENABLED,
  prepare: prepareMergeRecord,
  commit: commitMergeRecord,
};
// endregion

// region queries
export const findMergeRecordById = async (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityMergeRecord>(context, user, id, ENTITY_TYPE_MERGE_RECORD);
};

export const findMergeRecordsPaginated = async (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityMergeRecord>) => {
  return pageEntitiesConnection<BasicStoreEntityMergeRecord>(context, user, [ENTITY_TYPE_MERGE_RECORD], opts);
};

export const isMergeRecordReversible = (record: BasicStoreEntityMergeRecord) => {
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
) => {
  if (movedFileIds.length === 0) return;
  const restoredFiles = [];
  const movedSet = new Set<string>();
  for (let index = 0; index < movedFileIds.length; index += 1) {
    const fileId = movedFileIds[index];
    const document = await loadFile(context, SYSTEM_USER, fileId, { dontThrow: true });
    if (!document) {
      logApp.warn('[CURATION] Merged file not found anymore, it cannot be moved back', { fileId });
      continue;
    }
    const restoredId = fileId.replace(`/${target.entity_type}/${target.internal_id}/`, `/${restored.entity_type}/${restored.internal_id}/`);
    const copied = await copyFile(context, { sourceId: fileId, targetId: restoredId, sourceDocument: document as any, targetEntityId: restored.internal_id });
    if (copied) {
      restoredFiles.push(storeFileConverter(user, copied));
      await deleteFile(context, SYSTEM_USER, fileId);
      movedSet.add(fileId);
    }
  }
  if (restoredFiles.length > 0) {
    await patchAttribute(context, SYSTEM_USER, restored.internal_id, restored.entity_type, { x_opencti_files: restoredFiles });
    const remaining = (target.x_opencti_files ?? []).filter((file) => !movedSet.has(file.id));
    await patchAttribute(context, SYSTEM_USER, target.internal_id, target.entity_type, { x_opencti_files: remaining });
  }
};

const recreateRelationship = async (context: AuthContext, user: AuthUser, relationship: MergeRecreatableRelationship) => {
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
  return createRelation(context, user, relationInput, { restore: true });
};

export interface UnmergeResult {
  record: BasicStoreEntityMergeRecord;
  restored_ids: string[];
  repointed_count: number;
  recreated_count: number;
  skipped_relationship_ids: string[];
}

/**
 * Revert a recorded merge, entirely or for some of its sources: the merged-away entities are recreated with their
 * original identifiers, attributes and references, the relationships they carried are re-pointed back (or recreated
 * when the merge had dropped them as duplicates), and what they brought to the target is removed from it.
 */
export const unmergeFromRecord = async (context: AuthContext, user: AuthUser, mergeRecordId: string, sourceIds?: string[] | null): Promise<UnmergeResult> => {
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
  const snapshot = record.merge_snapshot;
  const pendingSources = snapshot.sources.filter((source) => !source.reverted_at);
  const reverting = sourceIds && sourceIds.length > 0 ? pendingSources.filter((source) => sourceIds.includes(source.internal_id)) : pendingSources;
  if (reverting.length === 0) {
    throw FunctionalError('No merged entity left to restore for this merge record', { id: mergeRecordId, sourceIds });
  }
  const remaining = pendingSources.filter((source) => !reverting.includes(source));
  const lockIds = [mergeRecordId, record.merge_target_id];
  let lock;
  try {
    lock = await lockResources(lockIds);
    const target = await storeLoadByIdWithRefs<StoreObject>(context, user, record.merge_target_id);
    if (!target) {
      throw FunctionalError('The entity the merge produced does not exist anymore (deleted or merged again). Revert its most recent merge first.', {
        id: mergeRecordId,
        target_id: record.merge_target_id,
      });
    }
    controlUserConfidenceAgainstElement(user, target);
    // 1. Remove from the target what the reverted sources brought (identifiers first, to free them for the restore).
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
      const restored = await restoreEntityFromMergeSnapshot(context, user, restoreInput, source.entity_type);
      restoredIds.push(restored.internal_id);
      const restoredLoaded = await storeLoadByIdWithRefs<StoreObject>(context, SYSTEM_USER, restored.internal_id);
      const liveTarget = await storeLoadByIdWithRefs<StoreObject>(context, SYSTEM_USER, target.internal_id);
      if (restoredLoaded && liveTarget) {
        await moveFilesBack(context, user, liveTarget, restoredLoaded, source.moved_file_ids);
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
          await recreateRelationship(context, user, relationship);
          recreatedCount += 1;
        } catch (err) {
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
    });
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
  const expired = await pageEntitiesConnection<BasicStoreEntityMergeRecord>(context, SYSTEM_USER, [ENTITY_TYPE_MERGE_RECORD], { filters: filters as any, first: 500 });
  for (let index = 0; index < expired.edges.length; index += 1) {
    const record = expired.edges[index].node;
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
  return expired.edges.length;
};
// endregion
