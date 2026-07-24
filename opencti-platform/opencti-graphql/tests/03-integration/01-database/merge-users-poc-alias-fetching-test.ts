import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { addReport } from '../../../src/domain/report';
import { findCreators, resolveUserByIdFromCache } from '../../../src/domain/user';
import { deleteElementById, distributionEntities, updateAttribute } from '../../../src/database/middleware';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { EditOperation, FilterMode } from '../../../src/generated/graphql';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import type { BasicStoreEntity } from '../../../src/types/store';
import { getExplicitUserAccessRight, MEMBER_ACCESS_RIGHT_VIEW } from '../../../src/utils/access';
import { ADMIN_USER, getAuthUser, testContext, USER_EDITOR, USER_SECURITY } from '../../utils/testQuery';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { stixObjectOrRelationshipAddRefRelations } from '../../../src/domain/stixObjectOrStixRelationship';
import { RELATION_OBJECT_ASSIGNEE } from '../../../src/schema/stixRefRelationship';

const READ_REPORT_USERS_QUERY = gql`
  query report($id: String) {
    report(id: $id) {
      creators {
        id
      }
      objectAssignee {
        id
      }
      objectParticipant {
        id
      }
    }
  }
`;

describe('Merge-users PoC #2 - distributed alias policies', () => {
  let sourceUser: Awaited<ReturnType<typeof getAuthUser>>;
  let targetUser: Awaited<ReturnType<typeof getAuthUser>>;
  const reportIds: string[] = [];

  const enableAlias = () => {
    process.env.MERGE_POC_ALIAS_MAP = JSON.stringify({ [sourceUser.internal_id]: targetUser.internal_id });
  };

  const findReportIds = async (key: string, userId: string) => {
    const reports = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_CONTAINER_REPORT], {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: [key], values: [userId] }],
        filterGroups: [],
      },
    });
    return reports.map((report) => report.id);
  };

  beforeAll(async () => {
    delete process.env.MERGE_POC_ALIAS_MAP;
    sourceUser = await getAuthUser(USER_EDITOR.id);
    targetUser = await getAuthUser(USER_SECURITY.id);
    const report = await addReport(testContext, sourceUser, {
      name: 'Merge-users PoC alias - legacy source references',
      published: new Date().toISOString(),
      report_types: ['threat-report'],
      objectAssignee: [sourceUser.internal_id],
      objectParticipant: [sourceUser.internal_id],
    });
    reportIds.push(report.id);
  });

  afterEach(() => {
    delete process.env.MERGE_POC_ALIAS_MAP;
  });

  afterAll(async () => {
    delete process.env.MERGE_POC_ALIAS_MAP;
    await Promise.all(reportIds.map((id) => deleteElementById(
      testContext,
      ADMIN_USER,
      id,
      ENTITY_TYPE_CONTAINER_REPORT,
    )));
  });

  it('canonicalizes dedicated display loaders while keeping security principals exact', async () => {
    const readDisplayedUserIds = async () => {
      const result = await queryAsAdmin({ query: READ_REPORT_USERS_QUERY, variables: { id: reportIds[0] } });
      expect(result.errors).toBeUndefined();
      const report = result.data?.report as {
        creators: Array<{ id: string }>;
        objectAssignee: Array<{ id: string }>;
        objectParticipant: Array<{ id: string }>;
      };
      return {
        creators: report.creators.map(({ id }) => id),
        assignees: report.objectAssignee.map(({ id }) => id),
        participants: report.objectParticipant.map(({ id }) => id),
      };
    };

    expect(await readDisplayedUserIds()).toEqual({
      creators: [sourceUser.internal_id],
      assignees: [sourceUser.internal_id],
      participants: [sourceUser.internal_id],
    });
    enableAlias();
    expect(await readDisplayedUserIds()).toEqual({
      creators: [targetUser.internal_id],
      assignees: [targetUser.internal_id],
      participants: [targetUser.internal_id],
    });
    const principal = await resolveUserByIdFromCache(testContext, sourceUser.internal_id) as { internal_id: string } | undefined;
    expect(principal?.internal_id).toEqual(sourceUser.internal_id);
  });

  it('expands operational filters over physically unchanged legacy data', async () => {
    const legacyReportId = reportIds[0];
    enableAlias();
    expect(await findReportIds('creator_id', targetUser.internal_id)).toContain(legacyReportId);
    expect(await findReportIds('objectAssignee', targetUser.internal_id)).toContain(legacyReportId);
    expect(await findReportIds('objectParticipant', targetUser.internal_id)).toContain(legacyReportId);

    delete process.env.MERGE_POC_ALIAS_MAP;
    expect(await findReportIds('creator_id', targetUser.internal_id)).not.toContain(legacyReportId);
    expect(await findReportIds('creator_id', sourceUser.internal_id)).toContain(legacyReportId);
  });

  it('coalesces real distribution counts before limiting aggregation buckets', async () => {
    const targetReport = await addReport(testContext, targetUser, {
      name: 'Merge-users PoC alias - target aggregation bucket',
      published: new Date().toISOString(),
      report_types: ['threat-report'],
    });
    reportIds.push(targetReport.id);

    enableAlias();
    const creators = await findCreators(testContext, ADMIN_USER, {
      entityTypes: [ENTITY_TYPE_CONTAINER_REPORT],
    }) as { edges: Array<{ node: { id: string } }> };
    const creatorIds = creators.edges.map((edge) => edge.node.id);
    expect(creatorIds).toContain(targetUser.internal_id);
    expect(creatorIds).not.toContain(sourceUser.internal_id);

    const distribution = await distributionEntities(testContext, ADMIN_USER, [ENTITY_TYPE_CONTAINER_REPORT], {
      field: 'creator_id',
      limit: 10,
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['internal_id'], values: [reportIds[0], targetReport.id] }],
        filterGroups: [],
      },
    });
    expect(distribution).toHaveLength(1);
    expect(distribution[0].entity.internal_id).toEqual(targetUser.internal_id);
    expect(distribution[0].value).toEqual(2);
  });

  it('canonicalizes new creator, assignee, and participant references', async () => {
    enableAlias();
    const report = await addReport(testContext, sourceUser, {
      name: 'Merge-users PoC alias - canonical target references',
      published: new Date().toISOString(),
      report_types: ['threat-report'],
      objectAssignee: [sourceUser.internal_id],
      objectParticipant: [sourceUser.internal_id],
    });
    reportIds.push(report.id);

    delete process.env.MERGE_POC_ALIAS_MAP;
    expect(await findReportIds('creator_id', targetUser.internal_id)).toContain(report.id);
    expect(await findReportIds('objectAssignee', targetUser.internal_id)).toContain(report.id);
    expect(await findReportIds('objectParticipant', targetUser.internal_id)).toContain(report.id);
    expect(await findReportIds('creator_id', sourceUser.internal_id)).not.toContain(report.id);
  });

  it('canonicalizes generic updates and removes every equivalent physical reference', async () => {
    const report = await addReport(testContext, sourceUser, {
      name: 'Merge-users PoC alias - generic update paths',
      published: new Date().toISOString(),
      report_types: ['threat-report'],
      objectAssignee: [sourceUser.internal_id],
      objectParticipant: [sourceUser.internal_id],
    });
    reportIds.push(report.id);

    enableAlias();
    await updateAttribute(testContext, ADMIN_USER, report.id, ENTITY_TYPE_CONTAINER_REPORT, [
      { key: 'creator_id', value: [sourceUser.internal_id], operation: EditOperation.Replace },
      { key: 'objectParticipant', value: [sourceUser.internal_id], operation: EditOperation.Replace },
      { key: 'objectAssignee', value: [targetUser.internal_id], operation: EditOperation.Remove },
    ]);

    delete process.env.MERGE_POC_ALIAS_MAP;
    expect(await findReportIds('creator_id', targetUser.internal_id)).toContain(report.id);
    expect(await findReportIds('creator_id', sourceUser.internal_id)).not.toContain(report.id);
    expect(await findReportIds('objectParticipant', targetUser.internal_id)).toContain(report.id);
    expect(await findReportIds('objectParticipant', sourceUser.internal_id)).not.toContain(report.id);
    expect(await findReportIds('objectAssignee', targetUser.internal_id)).not.toContain(report.id);
    expect(await findReportIds('objectAssignee', sourceUser.internal_id)).not.toContain(report.id);
  });

  it('fails writes explicitly when an alias target user does not exist', async () => {
    const missingTargetId = '99999999-9999-4999-8999-999999999999';
    process.env.MERGE_POC_ALIAS_MAP = JSON.stringify({
      [sourceUser.internal_id]: missingTargetId,
    });

    await expect(addReport(testContext, sourceUser, {
      name: 'Merge-users PoC alias - invalid target must fail',
      published: new Date().toISOString(),
      report_types: ['threat-report'],
    })).rejects.toThrow('MERGE_POC_ALIAS_MAP target user cannot be resolved');

    await expect(stixObjectOrRelationshipAddRefRelations(
      testContext,
      ADMIN_USER,
      reportIds[0],
      { relationship_type: RELATION_OBJECT_ASSIGNEE, toIds: [sourceUser.internal_id] },
      ENTITY_TYPE_CONTAINER_REPORT,
    )).rejects.toThrow('MERGE_POC_ALIAS_MAP target users cannot be resolved');
  });

  it('keeps restricted-member access target-strict', () => {
    enableAlias();
    const element = {
      restricted_members: [{
        id: sourceUser.internal_id,
        access_right: MEMBER_ACCESS_RIGHT_VIEW,
        groups_restriction_ids: [],
      }],
      authorized_authorities: [],
    };
    expect(getExplicitUserAccessRight({ ...sourceUser, id: sourceUser.internal_id }, element)).toEqual(MEMBER_ACCESS_RIGHT_VIEW);
    expect(getExplicitUserAccessRight({ ...targetUser, id: targetUser.internal_id }, element)).toBeNull();
  });
});
