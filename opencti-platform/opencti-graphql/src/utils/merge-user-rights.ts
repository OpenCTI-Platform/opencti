// PoC merge-users #4 - rights & STIX refs transfer (dedup, no privilege escalation).
//
// This module is intentionally isolated: it is NEVER imported by production code. The
// "apply" function is only exercised by the dedicated integration test
// (tests/03-integration/01-database/merge-user-rights-poc-test.ts). The "plan" function
// is pure read (dry-run) and safe to call anywhere.
//
// Scope: transferring a User's RIGHTS (member-of a Group, participate-to an
// Organization) and STIX REFERENCES (created-by, object-assignee, object-participant)
// from a "source" user to a "target" user, without creating duplicates and without
// silently combining rights (see MergeUserRightsMode below).
//
// Explicitly OUT of scope (must never be touched here):
// - has-role / has-capability: those are carried by the Group entity, not by the User,
//   so there is nothing to transfer at the user level (see PoC #1 finding).
// - creator_id and any other simple `id`-format attribute: already proven feasible by
//   the schema-driven discovery of PoC #3, handled by a different mechanism.
// - Runtime state (Redis sessions, tokens, notifications, locks): out of scope, see the
//   "Résultats du PoC" / product questions in the PR description.
import { ENTITY_TYPE_GROUP } from '../schema/internalObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO } from '../schema/internalRelationship';
import { RELATION_CREATED_BY, RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_PARTICIPANT } from '../schema/stixRefRelationship';
import { ABSTRACT_STIX_CORE_OBJECT } from '../schema/general';
import { fullEntitiesThroughRelationsFromList, fullEntitiesThroughRelationsToList } from '../database/middleware-loader';
import { userAddRelation } from '../domain/user';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipDeleteRefRelation } from '../domain/stixObjectOrStixRelationship';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntity } from '../types/store';

/**
 * Product decision point (NOT decided here, see "Questions produit" in the PR):
 * - 'union': the target GAINS the memberships the source had and it did not
 *   (the target's rights become the union of both users' rights).
 * - 'target-strict': nothing is transferred, the target keeps exactly its own
 *   memberships ("we do not combine rights", per the spec reminder).
 * Both modes are implemented so that the impact of each can be observed and compared;
 * picking the one to keep in production is a product call.
 */
export type MergeUserRightsMode = 'union' | 'target-strict';

export type MembershipAction = 'add-to-target' | 'already-present-skip' | 'skip-strict-mode';

export type MembershipRelationType = typeof RELATION_MEMBER_OF | typeof RELATION_PARTICIPATE_TO;

export interface MembershipDiffItem {
  relationship_type: MembershipRelationType;
  entity_id: string;
  entity_type: string;
  entity_name: string;
  action: MembershipAction;
  note: string;
}

export type RefRelationType = typeof RELATION_CREATED_BY | typeof RELATION_OBJECT_ASSIGNEE | typeof RELATION_OBJECT_PARTICIPANT;

export type RefAction = 'move-to-target' | 'already-present-remove-source-only';

export interface RefTransferItem {
  relationship_type: RefRelationType;
  object_id: string;
  object_type: string;
  action: RefAction;
  note: string;
}

export interface MergeUserRightsPlan {
  source_id: string;
  target_id: string;
  mode: MergeUserRightsMode;
  memberships: MembershipDiffItem[];
  refs: RefTransferItem[];
}

const MEMBERSHIP_RELATIONS: Array<{ relationshipType: MembershipRelationType; entityType: string }> = [
  { relationshipType: RELATION_MEMBER_OF, entityType: ENTITY_TYPE_GROUP },
  { relationshipType: RELATION_PARTICIPATE_TO, entityType: ENTITY_TYPE_IDENTITY_ORGANIZATION },
];

// created-by is included per spec, but PoC #1 already found that, on a User account,
// this ref conventionally targets an Individual (linked to the user's email), not the
// User id itself. It is kept here for completeness / genericity: if some data does
// point created-by to a User id, it will still be picked up and handled like the others.
const REF_RELATIONS: RefRelationType[] = [RELATION_CREATED_BY, RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_PARTICIPANT];

const buildMembershipDiff = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  targetId: string,
  mode: MergeUserRightsMode,
): Promise<MembershipDiffItem[]> => {
  const diff: MembershipDiffItem[] = [];
  for (const { relationshipType, entityType } of MEMBERSHIP_RELATIONS) {
    // eslint-disable-next-line no-await-in-loop
    const sourceMemberships = await fullEntitiesThroughRelationsToList<BasicStoreEntity>(context, user, sourceId, relationshipType, entityType);
    // eslint-disable-next-line no-await-in-loop
    const targetMemberships = await fullEntitiesThroughRelationsToList<BasicStoreEntity>(context, user, targetId, relationshipType, entityType);
    const targetMembershipIds = new Set(targetMemberships.map((membership) => membership.internal_id));
    for (const membership of sourceMemberships) {
      const alreadyOnTarget = targetMembershipIds.has(membership.internal_id);
      let action: MembershipAction;
      let note: string;
      if (alreadyOnTarget) {
        action = 'already-present-skip';
        note = 'déjà présent (ignoré) : target has this membership already, no duplicate created';
      } else if (mode === 'union') {
        action = 'add-to-target';
        note = 'union mode: missing on target, added';
      } else {
        action = 'skip-strict-mode';
        note = 'target-strict mode: not transferred, target rights are left untouched';
      }
      diff.push({
        relationship_type: relationshipType,
        entity_id: membership.internal_id,
        entity_type: membership.entity_type,
        entity_name: membership.name,
        action,
        note,
      });
    }
  }
  return diff;
};

const buildRefDiff = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  targetId: string,
): Promise<RefTransferItem[]> => {
  const diff: RefTransferItem[] = [];
  for (const relationshipType of REF_RELATIONS) {
    // eslint-disable-next-line no-await-in-loop
    const objectsReferencingSource = await fullEntitiesThroughRelationsFromList<BasicStoreEntity>(context, user, sourceId, relationshipType, ABSTRACT_STIX_CORE_OBJECT);
    // eslint-disable-next-line no-await-in-loop
    const objectsReferencingTarget = await fullEntitiesThroughRelationsFromList<BasicStoreEntity>(context, user, targetId, relationshipType, ABSTRACT_STIX_CORE_OBJECT);
    const targetObjectIds = new Set(objectsReferencingTarget.map((object) => object.internal_id));
    for (const object of objectsReferencingSource) {
      const alreadyOnTarget = targetObjectIds.has(object.internal_id);
      diff.push({
        relationship_type: relationshipType,
        object_id: object.internal_id,
        object_type: object.entity_type,
        action: alreadyOnTarget ? 'already-present-remove-source-only' : 'move-to-target',
        note: alreadyOnTarget
          ? 'déjà présent (ignoré) : object already references target, only the source ref is removed'
          : 'not referencing target yet: ref moved from source to target',
      });
    }
  }
  return diff;
};

/**
 * Computes the transfer PLAN for a (sourceId, targetId) pair. Pure read/dry-run: it
 * never writes anything, so it is always safe to call.
 */
export const buildMergeUserRightsPlan = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  targetId: string,
  mode: MergeUserRightsMode = 'union',
): Promise<MergeUserRightsPlan> => {
  const [memberships, refs] = await Promise.all([
    buildMembershipDiff(context, user, sourceId, targetId, mode),
    buildRefDiff(context, user, sourceId, targetId),
  ]);
  return {
    source_id: sourceId, target_id: targetId, mode, memberships, refs,
  };
};

/**
 * Applies a previously computed plan.
 *
 * IMPORTANT: this function must NEVER be called from production code. It is exercised
 * only by the dedicated integration test, which is the only place allowed to import it
 * for a real apply. Building a fresh plan before applying (as the test does) is what
 * makes re-running the transfer idempotent: already-transferred items are reported as
 * "already-present" and skipped, so applying twice never creates a duplicate.
 */
export const applyMergeUserRightsPlan = async (context: AuthContext, user: AuthUser, plan: MergeUserRightsPlan): Promise<void> => {
  for (const item of plan.memberships) {
    if (item.action === 'add-to-target') {
      // eslint-disable-next-line no-await-in-loop
      await userAddRelation(context, user, plan.target_id, { toId: item.entity_id, relationship_type: item.relationship_type });
    }
    // 'already-present-skip' and 'skip-strict-mode' are no-ops on purpose: memberships
    // are never removed from the source by this PoC (the source user is expected to be
    // deleted as part of the broader merge flow, which cascades relation deletion).
  }
  for (const item of plan.refs) {
    if (item.action === 'move-to-target') {
      // eslint-disable-next-line no-await-in-loop
      await stixObjectOrRelationshipAddRefRelation(
        context,
        user,
        item.object_id,
        { relationship_type: item.relationship_type, toId: plan.target_id },
        ABSTRACT_STIX_CORE_OBJECT,
      );
    }
    // In both cases the ref towards the source must be removed: either because it was
    // just replaced by the target ref, or because the target already had it and the
    // source ref is now a pure duplicate.
    // eslint-disable-next-line no-await-in-loop
    await stixObjectOrRelationshipDeleteRefRelation(
      context,
      user,
      item.object_id,
      plan.source_id,
      item.relationship_type,
      ABSTRACT_STIX_CORE_OBJECT,
    );
  }
};
