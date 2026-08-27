import { fullRelationsList } from '../../database/middleware-loader';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipDeleteRefRelation } from '../../domain/stixObjectOrStixRelationship';
import { ABSTRACT_INTERNAL_OBJECT, ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_PARTICIPANT } from '../../schema/stixRefRelationship';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { type UserMergeHandler, type UserMergeHandlerContext, type UserMergeHandlerPlan, type UserMergePlannedChange } from './userMerge-handler';

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
 * `DraftWorkspace` carries assignees and participants while being an internal object, so the
 * abstract type cannot be assumed from the relation alone.
 */
const abstractTypeOf = (entityType: string): string => {
  return isStixCoreObject(entityType) ? ABSTRACT_STIX_CORE_OBJECT : ABSTRACT_INTERNAL_OBJECT;
};

/**
 * Re-points the operational relations of the source user onto the target.
 *
 * Assignment and participation are `multiple: true` refs, so a user merge can leave an element
 * naming the target twice. The redundant edge is dropped at plan time rather than at write time,
 * which is also what makes replaying the merge a no-op.
 *
 * Relations go through the domain layer rather than a bulk rewrite: only the entity side is
 * denormalized — `object-assignee_to` and `object-participant_to` are declared unimpacted — and a
 * raw index write would leave `rel_object-assignee.internal_id` naming a user the relation no
 * longer points at.
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
      changes.push({ register_row_id: relation.registerRow, entity_type: relation.relationshipType, count: plan.repointed.length, exact: true, detail: REPOINTED });
      changes.push({ register_row_id: relation.registerRow, entity_type: relation.relationshipType, count: plan.deduplicated.length, exact: true, detail: DEDUPLICATED });
    }
    return { handler: USER_MERGE_OPERATIONAL_RELATIONS_HANDLER, changes, alerts: [] };
  },
  apply: async ({ context, sourceId, targetId }: UserMergeHandlerContext): Promise<number> => {
    let updated = 0;
    for (let i = 0; i < OPERATIONAL_RELATIONS.length; i += 1) {
      const relation = OPERATIONAL_RELATIONS[i];
      const relationPlan = await readOperationalPlan(context, relation, sourceId, targetId);
      for (let repointed = 0; repointed < relationPlan.repointed.length; repointed += 1) {
        const entity = relationPlan.repointed[repointed];
        const abstractType = abstractTypeOf(entity.type);
        // Added before the source edge is dropped, so the element is never left unassigned.
        await stixObjectOrRelationshipAddRefRelation(context, SYSTEM_USER, entity.id, { relationship_type: relation.relationshipType, toId: targetId }, abstractType);
        await stixObjectOrRelationshipDeleteRefRelation(context, SYSTEM_USER, entity.id, sourceId, relation.relationshipType, abstractType);
        updated += 1;
      }
      for (let deduplicated = 0; deduplicated < relationPlan.deduplicated.length; deduplicated += 1) {
        const entity = relationPlan.deduplicated[deduplicated];
        await stixObjectOrRelationshipDeleteRefRelation(context, SYSTEM_USER, entity.id, sourceId, relation.relationshipType, abstractTypeOf(entity.type));
        updated += 1;
      }
    }
    return updated;
  },
};
