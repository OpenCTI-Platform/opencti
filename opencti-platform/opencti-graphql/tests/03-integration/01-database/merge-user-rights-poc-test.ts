import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, getAuthUser, testContext, USER_EDITOR, USER_SECURITY } from '../../utils/testQuery';
import { assignGroupToUser } from '../../../src/domain/user';
import { addReport } from '../../../src/domain/report';
import { stixObjectOrRelationshipAddRefRelation } from '../../../src/domain/stixObjectOrStixRelationship';
import { deleteElementById, deleteRelationsByFromAndTo } from '../../../src/database/middleware';
import { fullEntitiesThroughRelationsToList } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { RELATION_MEMBER_OF } from '../../../src/schema/internalRelationship';
import { RELATION_CREATED_BY, RELATION_OBJECT_ASSIGNEE } from '../../../src/schema/stixRefRelationship';
import { ABSTRACT_INTERNAL_RELATIONSHIP, ABSTRACT_STIX_CORE_OBJECT } from '../../../src/schema/general';
import { controlUserRestrictDeleteAgainstElement } from '../../../src/utils/access';
import { generateStandardId } from '../../../src/schema/identifier';
import type { BasicStoreEntity } from '../../../src/types/store';
import { buildMergeUserRightsPlan, applyMergeUserRightsPlan } from '../../../src/utils/merge-user-rights';

/**
 * PoC #4 (merge-users investigation) - rights & STIX refs transfer.
 *
 * This is the "real hard part" of variant B: transferring memberships (member-of a
 * Group, participate-to an Organization) and STIX refs (created-by, object-assignee,
 * object-participant) from a "source" user to a "target" user, without ever creating a
 * duplicate and without silently combining rights.
 *
 * Source user: USER_EDITOR (member of AMBER_GROUP by default)
 * Target user: USER_SECURITY (member of AMBER_STRICT_GROUP by default)
 * Both are additionally made members of GREEN_GROUP here, to reproduce the "already
 * shared" case.
 */
describe('Merge-users PoC #4 - rights & STIX refs transfer (dedup, no escalation)', () => {
  let sourceUser: Awaited<ReturnType<typeof getAuthUser>>;
  let targetUser: Awaited<ReturnType<typeof getAuthUser>>;
  let reportBothAssigned: { id: string };
  let reportSourceOnlyAssigned: { id: string };
  let reportCreatedBySource: { id: string; entity_type: string; creator_id?: string | string[] };

  beforeAll(async () => {
    sourceUser = await getAuthUser(USER_EDITOR.id);
    targetUser = await getAuthUser(USER_SECURITY.id);

    // Defensive cleanup: a previous (interrupted) run of this suite may have already
    // transferred AMBER_GROUP to the target. Make the suite self-healing so it can be
    // re-run from a deterministic state without a full platform reset.
    const amberGroupId = generateStandardId(ENTITY_TYPE_GROUP, { name: 'AMBER GROUP' });
    await deleteRelationsByFromAndTo(testContext, ADMIN_USER, targetUser.internal_id, amberGroupId, RELATION_MEMBER_OF, ABSTRACT_INTERNAL_RELATIONSHIP).catch(() => {
      // Relation may not exist: ignore.
    });

    // Case (a) setup: both source and target already belong to the SAME group.
    await assignGroupToUser(testContext, ADMIN_USER, sourceUser.internal_id, 'GREEN GROUP');
    await assignGroupToUser(testContext, ADMIN_USER, targetUser.internal_id, 'GREEN GROUP');
    // AMBER_GROUP is left as-is: only the source is a member of it by default test data
    // (case b: a group the source has that the target does not).

    // Case (c) setup: an object assigned to BOTH source and target already.
    reportBothAssigned = await addReport(testContext, ADMIN_USER, {
      name: 'PoC#4 - report assigned to both source and target',
      published: new Date().toISOString(),
      report_types: ['threat-report'],
      objectAssignee: [sourceUser.internal_id, targetUser.internal_id],
    });

    // Case (d) setup: an object assigned to the source ONLY.
    reportSourceOnlyAssigned = await addReport(testContext, ADMIN_USER, {
      name: 'PoC#4 - report assigned to source only',
      published: new Date().toISOString(),
      report_types: ['threat-report'],
      objectAssignee: [sourceUser.internal_id],
    });

    // Case (e) setup: an object CREATED BY the source (creator_id), used to prove that
    // this rights/refs transfer never touches creator_id (out of scope, see PoC #3).
    reportCreatedBySource = await addReport(testContext, sourceUser, {
      name: 'PoC#4 - report created by source (creator_id check)',
      published: new Date().toISOString(),
      report_types: ['threat-report'],
    });
  });

  afterAll(async () => {
    for (const reportId of [reportBothAssigned?.id, reportSourceOnlyAssigned?.id, reportCreatedBySource?.id]) {
      if (reportId) {
        // eslint-disable-next-line no-await-in-loop
        await deleteElementById(testContext, ADMIN_USER, reportId, ENTITY_TYPE_CONTAINER_REPORT);
      }
    }
    // Clean up the memberships added by this test (both the beforeAll setup and the
    // merge apply itself), so re-running the suite starts from a deterministic state.
    // GREEN_GROUP was added to both users by this test's beforeAll: remove it from both.
    // AMBER_GROUP is source's default fixture group (not added by us): only remove the
    // copy the merge added to the target, never touch the source's default membership.
    const greenGroupId = generateStandardId(ENTITY_TYPE_GROUP, { name: 'GREEN GROUP' });
    const amberGroupId = generateStandardId(ENTITY_TYPE_GROUP, { name: 'AMBER GROUP' });
    for (const userId of [sourceUser?.internal_id, targetUser?.internal_id]) {
      if (userId) {
        // eslint-disable-next-line no-await-in-loop
        await deleteRelationsByFromAndTo(testContext, ADMIN_USER, userId, greenGroupId, RELATION_MEMBER_OF, ABSTRACT_INTERNAL_RELATIONSHIP).catch(() => {
          // Relation may already be gone: ignore.
        });
      }
    }
    if (targetUser?.internal_id) {
      await deleteRelationsByFromAndTo(testContext, ADMIN_USER, targetUser.internal_id, amberGroupId, RELATION_MEMBER_OF, ABSTRACT_INTERNAL_RELATIONSHIP).catch(() => {
        // Relation may not have been added (e.g. if the union-mode test did not run): ignore.
      });
    }
  });

  it('[Plan] should build a plan describing dedup for a shared group and diff for a source-only group', async () => {
    const plan = await buildMergeUserRightsPlan(testContext, ADMIN_USER, sourceUser.internal_id, targetUser.internal_id, 'union');

    const greenGroupItem = plan.memberships.find((item) => item.entity_name === 'GREEN GROUP');
    expect(greenGroupItem?.action).toEqual('already-present-skip');

    const amberGroupItem = plan.memberships.find((item) => item.entity_name === 'AMBER GROUP');
    expect(amberGroupItem?.action).toEqual('add-to-target');

    const reportBothItem = plan.refs.find((item) => item.object_id === reportBothAssigned.id && item.relationship_type === RELATION_OBJECT_ASSIGNEE);
    expect(reportBothItem?.action).toEqual('already-present-remove-source-only');

    const reportSourceOnlyItem = plan.refs.find((item) => item.object_id === reportSourceOnlyAssigned.id && item.relationship_type === RELATION_OBJECT_ASSIGNEE);
    expect(reportSourceOnlyItem?.action).toEqual('move-to-target');
  });

  it('[Plan] "target-strict" mode should never add the source-only group to the target', async () => {
    const plan = await buildMergeUserRightsPlan(testContext, ADMIN_USER, sourceUser.internal_id, targetUser.internal_id, 'target-strict');
    const amberGroupItem = plan.memberships.find((item) => item.entity_name === 'AMBER GROUP');
    expect(amberGroupItem?.action).toEqual('skip-strict-mode');
  });

  it('(a)+(b) [union] should add the source-only group to the target and never duplicate the shared group', async () => {
    const plan = await buildMergeUserRightsPlan(testContext, ADMIN_USER, sourceUser.internal_id, targetUser.internal_id, 'union');
    await applyMergeUserRightsPlan(testContext, ADMIN_USER, plan);

    const targetGroups = await fullEntitiesThroughRelationsToList<BasicStoreEntity>(testContext, ADMIN_USER, targetUser.internal_id, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP);
    const targetGroupNames = targetGroups.map((group) => group.name);

    // (b) union mode: the target gained the source-only group.
    expect(targetGroupNames.filter((name) => name === 'AMBER GROUP').length).toEqual(1);
    // (a) the shared group is present exactly once: no duplicate membership was created.
    expect(targetGroupNames.filter((name) => name === 'GREEN GROUP').length).toEqual(1);
  });

  it('[Idempotence] re-building and re-applying the plan should not create a duplicate membership', async () => {
    const plan = await buildMergeUserRightsPlan(testContext, ADMIN_USER, sourceUser.internal_id, targetUser.internal_id, 'union');
    // Everything is already transferred: the plan must report every item as already
    // present, there is nothing left to add.
    expect(plan.memberships.every((item) => item.action !== 'add-to-target')).toEqual(true);

    await applyMergeUserRightsPlan(testContext, ADMIN_USER, plan);

    const targetGroups = await fullEntitiesThroughRelationsToList<BasicStoreEntity>(testContext, ADMIN_USER, targetUser.internal_id, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP);
    const targetGroupNames = targetGroups.map((group) => group.name);
    expect(targetGroupNames.filter((name) => name === 'AMBER GROUP').length).toEqual(1);
    expect(targetGroupNames.filter((name) => name === 'GREEN GROUP').length).toEqual(1);
  });

  it('(c)+(d) should transfer object-assignee refs to the target, deduplicating the already-shared assignment', async () => {
    const plan = await buildMergeUserRightsPlan(testContext, ADMIN_USER, sourceUser.internal_id, targetUser.internal_id, 'union');
    await applyMergeUserRightsPlan(testContext, ADMIN_USER, plan);

    const assigneesOfReportBoth = await fullEntitiesThroughRelationsToList<BasicStoreEntity>(
      testContext,
      ADMIN_USER,
      reportBothAssigned.id,
      RELATION_OBJECT_ASSIGNEE,
      ENTITY_TYPE_USER,
      { withInferences: false },
    );
    // (c) was assigned to both: after the transfer, only the target remains (source
    // removed, target NOT duplicated).
    expect(assigneesOfReportBoth.map((u) => u.internal_id)).toEqual([targetUser.internal_id]);

    const assigneesOfReportSourceOnly = await fullEntitiesThroughRelationsToList<BasicStoreEntity>(
      testContext,
      ADMIN_USER,
      reportSourceOnlyAssigned.id,
      RELATION_OBJECT_ASSIGNEE,
      ENTITY_TYPE_USER,
      { withInferences: false },
    );
    // (d) was assigned to source only: after the transfer, the target is the sole assignee.
    expect(assigneesOfReportSourceOnly.map((u) => u.internal_id)).toEqual([targetUser.internal_id]);
  });

  it('[Idempotence] re-building and re-applying the refs plan should not create a duplicate assignment nor fail', async () => {
    const plan = await buildMergeUserRightsPlan(testContext, ADMIN_USER, sourceUser.internal_id, targetUser.internal_id, 'union');
    // Nothing left to move: every ref pointing to the source has already been handled.
    expect(plan.refs.length).toEqual(0);

    await expect(applyMergeUserRightsPlan(testContext, ADMIN_USER, plan)).resolves.not.toThrow();

    const assigneesOfReportBoth = await fullEntitiesThroughRelationsToList<BasicStoreEntity>(
      testContext,
      ADMIN_USER,
      reportBothAssigned.id,
      RELATION_OBJECT_ASSIGNEE,
      ENTITY_TYPE_USER,
      { withInferences: false },
    );
    expect(assigneesOfReportBoth.map((u) => u.internal_id)).toEqual([targetUser.internal_id]);
  });

  it('[created-by structural finding] created-by cannot target a User id (confirms PoC #1)', async () => {
    // This documents WHY buildMergeUserRightsPlan.refs never contains a created-by item
    // pointing to a User in practice: the platform enforces that created-by can only
    // target an Identity entity (validateCreatedBy), and User is not a STIX Identity.
    await expect(stixObjectOrRelationshipAddRefRelation(
      testContext,
      ADMIN_USER,
      reportSourceOnlyAssigned.id,
      { relationship_type: RELATION_CREATED_BY, toId: sourceUser.internal_id },
      ABSTRACT_STIX_CORE_OBJECT,
    )).rejects.toThrow();
  });

  it('(e) the object-assignee/participant transfer must NOT affect controlUserRestrictDeleteAgainstElement (creator_id untouched)', async () => {
    // This module never touches creator_id: it is handled by a different mechanism
    // (PoC #3, schema-driven id rewrite). We prove here that granting the target the
    // source's assignee/participant refs does not accidentally grant it "restrict_delete"
    // bypass, which is based solely on creator_id.
    const restrictedTargetUser = { ...targetUser, restrict_delete: true };
    const restrictedSourceUser = { ...sourceUser, restrict_delete: true };

    // The target never created this report (creator_id === source): restrict_delete
    // must still forbid it, no matter what refs it has been assigned.
    expect(() => controlUserRestrictDeleteAgainstElement(restrictedTargetUser, reportCreatedBySource)).toThrow();
    // The source is still the technical creator: restrict_delete must still allow it.
    expect(controlUserRestrictDeleteAgainstElement(restrictedSourceUser, reportCreatedBySource)).toEqual(true);
  });
});
