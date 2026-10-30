import { elRawCount } from '../../database/engine';
import { fullRelationsList } from '../../database/middleware-loader';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipDeleteRefRelation } from '../../domain/stixObjectOrStixRelationship';
import { ABSTRACT_INTERNAL_OBJECT, ABSTRACT_STIX_CORE_OBJECT, buildRefRelationKey } from '../../schema/general';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_PARTICIPANT } from '../../schema/stixRefRelationship';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { INDEX_DELETED_OBJECTS, READ_INDEX_DRAFT_OBJECTS } from '../../database/utils';
import { userMergeBulkDelete, userMergeBulkUpdate, type UserMergeRewriteCandidate, userMergeScanForRewrite } from './userMerge-bulk';
import { USER_MERGE_SILENT_WRITE, type UserMergeHandler, type UserMergeHandlerContext, type UserMergeHandlerPlan, type UserMergePlannedChange } from './userMerge-handler';

export const USER_MERGE_OPERATIONAL_RELATIONS_HANDLER = 'operational-relations';

/** A STIX ref relation whose `to` side is the user being merged. */
interface OperationalRelation {
  registerRow: string;
  relationshipType: string;
}

const OPERATIONAL_RELATIONS: OperationalRelation[] = [
  { registerRow: 'object-assignee.connections', relationshipType: RELATION_OBJECT_ASSIGNEE },
  { registerRow: 'object-participant.connections', relationshipType: RELATION_OBJECT_PARTICIPANT },
];

const REPOINTED = 're-pointed to the target';
const DEDUPLICATED = 'already held by the target, source edge dropped';
const TRASHED = 'rewritten in the trash';
const DRAFTED = 'rewritten inside a draft';
const DRAFT_DEDUPLICATED = 'already held by the target inside a draft, source edge dropped';

const relationPaths = OPERATIONAL_RELATIONS.map((relation) => `${relation.relationshipType}.connections`);

interface OperationalPlan {
  /** Entities referencing the source and not the target. */
  repointed: { id: string; type: string }[];
  /** Entities referencing both, where the source edge is redundant. */
  deduplicated: { id: string; type: string }[];
}

/**
 * The entity is the `from` side of these relations, the user the `to` side, which is the reverse
 * of the rights relations of the previous chunk. The plan is therefore read by `toId`, and what it
 * names is the referencing entity rather than the relation.
 */
const readOperationalPlan = async (
  context: AuthContext,
  relation: OperationalRelation,
  sourceId: string,
  targetId: string,
): Promise<OperationalPlan> => {
  const sourceRelations = await fullRelationsList(context, SYSTEM_USER, relation.relationshipType, { toId: sourceId });
  const targetRelations = await fullRelationsList(context, SYSTEM_USER, relation.relationshipType, { toId: targetId });
  const held = new Set(targetRelations.map((targetRelation) => targetRelation.fromId));
  const repointed: { id: string; type: string }[] = [];
  const deduplicated: { id: string; type: string }[] = [];
  for (let i = 0; i < sourceRelations.length; i += 1) {
    const sourceRelation = sourceRelations[i];
    const entity = { id: sourceRelation.fromId, type: sourceRelation.fromType };
    if (held.has(sourceRelation.fromId)) {
      deduplicated.push(entity);
    } else {
      repointed.push(entity);
    }
  }
  return { repointed, deduplicated };
};

/**
 * The abstract root the referencing entity has to be announced under.
 *
 * The relationship helpers resolve their bus topic with `BUS_TOPICS[type].EDIT_TOPIC`, where these
 * two are the only abstract roots registered, so passing any other one throws. Assignees and
 * participants are carried by Stix core objects everywhere except on `DraftWorkspace`, an internal
 * object, which is why the root is derived from the entity rather than held as a constant.
 */
const abstractTypeOf = (entityType: string): string => {
  return isStixCoreObject(entityType) ? ABSTRACT_STIX_CORE_OBJECT : ABSTRACT_INTERNAL_OBJECT;
};

/**
 * Copies held outside live data — in the trash and in drafts — matched either as the relation
 * itself or as the denormalized array the referencing entity carries.
 *
 * Restoring an element whose assignee is a user that no longer exists would re-inject the source
 * id into live data, which is what the trash is included for. A draft is read in its own context,
 * which the live path above never enters: its copies keep naming the source, and validating a
 * draft sends an entity it created with the assignees of its draft relations.
 */
const copiesQuery = (relation: OperationalRelation, sourceId: string): Record<string, unknown> => ({
  bool: {
    should: [
      {
        bool: {
          must: [
            { term: { 'entity_type.keyword': relation.relationshipType } },
            { nested: { path: 'connections', query: { term: { 'connections.internal_id.keyword': sourceId } } } },
          ],
        },
      },
      { term: { [`${buildRefRelationKey(relation.relationshipType)}.keyword`]: sourceId } },
    ],
    minimum_should_match: 1,
  },
});

/**
 * The connections rewrite is guarded by the relation type because a document can match on the
 * denormalized array while being a relation of another type — whose own connections belong to
 * another handler. A connection carries the name of its element next to its id, so both move.
 */
const copiesScript = (relation: OperationalRelation, sourceId: string, targetId: string, targetName: string) => {
  const refKey = buildRefRelationKey(relation.relationshipType);
  return {
    source: 'if (ctx._source.entity_type == params.type && ctx._source.connections != null) {'
      + ' for (connection in ctx._source.connections) {'
      + ' if (connection.internal_id == params.source) { connection.internal_id = params.target; connection.name = params.targetName; } } }'
      + ` if (ctx._source['${refKey}'] != null && ctx._source['${refKey}'].contains(params.source)) {`
      + ` ctx._source['${refKey}'].removeIf(reference -> reference.equals(params.source));`
      + ` if (!ctx._source['${refKey}'].contains(params.target)) { ctx._source['${refKey}'].add(params.target); } }`,
    lang: 'painless',
    params: { type: relation.relationshipType, source: sourceId, target: targetId, targetName },
  };
};

/**
 * Draft relations to the source whose referencing entity already holds the target in the same
 * draft, deleted rather than re-pointed so that the draft does not name the target twice.
 *
 * Whether the target is held is read from the denormalized array of the entity copy in that
 * draft, which reflects what the draft shows: the live relations it copied and its own edits.
 */
const readDraftDuplicates = async (
  context: AuthContext,
  relation: OperationalRelation,
  sourceId: string,
  targetId: string,
): Promise<UserMergeRewriteCandidate[]> => {
  const relations = await userMergeScanForRewrite(context, [READ_INDEX_DRAFT_OBJECTS], {
    bool: {
      must: [
        { term: { 'entity_type.keyword': relation.relationshipType } },
        { nested: { path: 'connections', query: { term: { 'connections.internal_id.keyword': sourceId } } } },
      ],
    },
  });
  if (relations.length === 0) {
    return [];
  }
  const fromRole = `${relation.relationshipType}_from`;
  const fromOf = (candidate: UserMergeRewriteCandidate): string | undefined => {
    return (candidate.source.connections ?? []).find((connection: { role: string }) => connection.role === fromRole)?.internal_id;
  };
  const fromIds = Array.from(new Set(relations.map(fromOf).filter((id): id is string => id !== undefined)));
  const holders = await userMergeScanForRewrite(context, [READ_INDEX_DRAFT_OBJECTS], {
    bool: {
      must: [
        { terms: { 'internal_id.keyword': fromIds } },
        { term: { [`${buildRefRelationKey(relation.relationshipType)}.keyword`]: targetId } },
      ],
    },
  });
  const held = new Set(holders.flatMap((holder) => (holder.source.draft_ids ?? []).map((draftId: string) => `${holder.source.internal_id}|${draftId}`)));
  return relations.filter((candidate) => (candidate.source.draft_ids ?? []).some((draftId: string) => held.has(`${fromOf(candidate)}|${draftId}`)));
};

/**
 * Re-points the operational relations of the source user onto the target.
 *
 * Assignment and participation are `multiple: true` refs, so a user merge can leave an element
 * naming the target twice. The redundant edge is dropped at plan time rather than at write time,
 * which is also what makes replaying the merge a no-op.
 *
 * Live relations go through the domain layer rather than a bulk rewrite: only the entity side is
 * denormalized — `object-assignee_to` and `object-participant_to` are declared unimpacted — and a
 * raw index write would leave `rel_object-assignee.internal_id` naming a user the relation no
 * longer points at. Deleted copies have no domain path and are rewritten in place; deduplicating
 * them is pointless, since a restored element is read through a `uniq` on that array.
 *
 * Draft copies are rewritten in place too: the domain path would record the re-pointing as a
 * draft edit, putting the source back into the draft patch. Unlike the trash, a draft is
 * deduplicated, since its relations are what it shows and what validating it creates.
 *
 * The live re-pointing replaces the relation rather than editing it, so a draft edit made on the
 * live relation of the source loses its hold on the new one: a draft that removed the source
 * shows the target as assigned, and one that swapped the source for the target shows it twice.
 * Only the preview is off. Validating an edited entity replays the draft patch, which the blobs
 * handler rewrites, and lands on the right assignees.
 */
export const userMergeOperationalRelationsHandler: UserMergeHandler = {
  identifier: USER_MERGE_OPERATIONAL_RELATIONS_HANDLER,
  covers: OPERATIONAL_RELATIONS.map((relation) => relation.registerRow),
  reads: relationPaths,
  writes: relationPaths,
  compute: async ({ context, sourceId, targetId }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const changes: UserMergePlannedChange[] = [];
    for (let i = 0; i < OPERATIONAL_RELATIONS.length; i += 1) {
      const relation = OPERATIONAL_RELATIONS[i];
      const plan = await readOperationalPlan(context, relation, sourceId, targetId);
      const trashed = await elRawCount({ index: [INDEX_DELETED_OBJECTS], body: { query: copiesQuery(relation, sourceId) } });
      const draftDuplicates = await readDraftDuplicates(context, relation, sourceId, targetId);
      // The duplicates are deleted before the rewrite, so the rewrite does not reach them.
      const drafted = await elRawCount({ index: [READ_INDEX_DRAFT_OBJECTS], body: { query: copiesQuery(relation, sourceId) } }) - draftDuplicates.length;
      changes.push({ register_row_id: relation.registerRow, entity_type: relation.relationshipType, count: plan.repointed.length, exact: true, detail: REPOINTED });
      changes.push({ register_row_id: relation.registerRow, entity_type: relation.relationshipType, count: plan.deduplicated.length, exact: true, detail: DEDUPLICATED });
      changes.push({ register_row_id: relation.registerRow, entity_type: relation.relationshipType, count: trashed, exact: true, detail: TRASHED });
      changes.push({ register_row_id: relation.registerRow, entity_type: relation.relationshipType, count: drafted, exact: true, detail: DRAFTED });
      changes.push({ register_row_id: relation.registerRow, entity_type: relation.relationshipType, count: draftDuplicates.length, exact: true, detail: DRAFT_DEDUPLICATED });
    }
    return { handler: USER_MERGE_OPERATIONAL_RELATIONS_HANDLER, changes, alerts: [] };
  },
  apply: async ({ context, sourceId, targetId, targetUser }: UserMergeHandlerContext, plan: UserMergeHandlerPlan): Promise<number> => {
    let updated = 0;
    for (let i = 0; i < OPERATIONAL_RELATIONS.length; i += 1) {
      const relation = OPERATIONAL_RELATIONS[i];
      const relationPlan = await readOperationalPlan(context, relation, sourceId, targetId);
      for (let repointed = 0; repointed < relationPlan.repointed.length; repointed += 1) {
        const entity = relationPlan.repointed[repointed];
        const abstractType = abstractTypeOf(entity.type);
        // Added before the source edge is dropped, so the element is never left unassigned.
        await stixObjectOrRelationshipAddRefRelation(
          context,
          SYSTEM_USER,
          entity.id,
          { relationship_type: relation.relationshipType, toId: targetId },
          abstractType,
          USER_MERGE_SILENT_WRITE,
        );
        await stixObjectOrRelationshipDeleteRefRelation(context, SYSTEM_USER, entity.id, sourceId, relation.relationshipType, abstractType, USER_MERGE_SILENT_WRITE);
        updated += 1;
      }
      for (let deduplicated = 0; deduplicated < relationPlan.deduplicated.length; deduplicated += 1) {
        const entity = relationPlan.deduplicated[deduplicated];
        await stixObjectOrRelationshipDeleteRefRelation(context, SYSTEM_USER, entity.id, sourceId, relation.relationshipType, abstractTypeOf(entity.type), USER_MERGE_SILENT_WRITE);
        updated += 1;
      }
      const planned = (detail: string) => plan.changes.some((change) => change.register_row_id === relation.registerRow && change.detail === detail && change.count > 0);
      const label = `${USER_MERGE_OPERATIONAL_RELATIONS_HANDLER}:${relation.registerRow}`;
      const script = copiesScript(relation, sourceId, targetId, targetUser.name);
      if (planned(TRASHED)) {
        const result = await userMergeBulkUpdate(label, [INDEX_DELETED_OBJECTS], { query: copiesQuery(relation, sourceId), script });
        updated += result.updated;
      }
      if (planned(DRAFT_DEDUPLICATED)) {
        const duplicates = await readDraftDuplicates(context, relation, sourceId, targetId);
        updated += await userMergeBulkDelete(context, label, duplicates.map(({ id, index }) => ({ id, index })));
      }
      if (planned(DRAFTED)) {
        const result = await userMergeBulkUpdate(label, [READ_INDEX_DRAFT_OBJECTS], { query: copiesQuery(relation, sourceId), script });
        updated += result.updated;
      }
    }
    return updated;
  },
};
