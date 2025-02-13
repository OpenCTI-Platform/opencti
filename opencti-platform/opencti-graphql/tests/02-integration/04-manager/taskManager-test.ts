import { afterAll, describe, expect, it } from 'vitest';
import type { BasicStoreEntity, StoreEntityReport } from '../../../src/types/store';
import { addStixCyberObservable } from '../../../src/domain/stixCyberObservable';
import type { AuthContext } from '../../../src/types/user';
import { ADMIN_USER, getUserIdByEmail, TEST_ORGANIZATION, testContext, USER_EDITOR } from '../../utils/testQuery';
import { addReport, findById as findReportById } from '../../../src/domain/report';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { generateFiltersForSharingTask } from '../../../src/domain/stix';
import { addStixCoreRelationship } from '../../../src/domain/stixCoreRelationship';
import { editAuthorizedMembers } from '../../../src/utils/authorizedMembers';
import { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../src/utils/access';
import { executeRemoveAuthMembers } from '../../../src/domain/stixCoreObject';
import { taskQuery } from '../../../src/manager/taskManager';

describe('TaskManager executeRemoveAuthMembers tests', () => {
  const adminContext: AuthContext = { user: ADMIN_USER, tracing: undefined, source: 'taskManager-integration-test', otp_mandatory: false };
  let reportId: string;
  afterAll(async () => {
    await stixDomainObjectDelete(adminContext, adminContext.user, reportId); // + 1 delete
    const report = await findReportById(adminContext, adminContext.user, reportId);
    expect(report).toBeUndefined();
  });
  it('Should REMOVE authorized members', async () => {
    // Create Report + 1 create
    const reportInput = {
      name: 'test report remove authorized members',
      published: '2023-10-06T22:00:00.000Z',
    };
    const report = await addReport(adminContext, adminContext.user, reportInput);
    expect(report.id).toBeDefined();
    reportId = report.id;

    // Add authorized members : + 1 update
    const userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    if (adminContext.user) {
      await editAuthorizedMembers(adminContext, adminContext.user, {
        entityType: report.entityType,
        requiredCapabilities: [KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS],
        entityId: report.id,
        input: [
          {
            id: userEditorId,
            access_right: 'admin'
          }
        ]
      });
    }

    // Verify authorized members
    const reportWithAuthorizedMembers = await findReportById(adminContext, adminContext.user, reportId);
    expect(reportWithAuthorizedMembers.authorized_members).toEqual([
      {
        id: userEditorId,
        access_right: 'admin'
      }
    ]);

    // Admin user removes authorized members: + 1 update
    await executeRemoveAuthMembers(adminContext, adminContext.user, report);

    // Verify there are no authorized
    const reportAfterRemove = await findReportById(adminContext, adminContext.user, reportId);
    expect(reportAfterRemove.authorized_members).toBeUndefined();
  });
});

describe('TaskManager computeQueryTaskElements', () => {
  let observable1;
  let observable2;
  let createdReport: StoreEntityReport;

  it('Create data for test', async () => {
    const observable1Data = {
      type: 'Domain-Name',
      DomainName: { value: 'observable-in-report-querytask.com' },
    };

    const observable2Data = {
      type: 'Domain-Name',
      DomainName: { value: 'observable-in-report-querytask.fr' },
    };

    observable1 = await addStixCyberObservable(testContext, ADMIN_USER, observable1Data);
    observable2 = await addStixCyberObservable(testContext, ADMIN_USER, observable2Data);
    createdReport = await addReport(testContext, ADMIN_USER, {
      name: 'taskManager test - computeQueryTaskElements',
      published: '2024-10-06T22:00:00.000Z',
      description: 'report use for taskManager test purpose on orderMode',
      objects: [observable1.id, observable2.id]
    });
    const relationShipAddInput = {
      relationship_type: 'related-to',
      confidence: 100,
      description: '',
      killChainPhases: [],
      externalReferences: [],
      objectMarking: [],
      fromId: observable1.id,
      toId: observable2.id
    };
    await addStixCoreRelationship(testContext, ADMIN_USER, relationShipAddInput);
  });

  it('When order mode is set to asc it should be taken', async () => {
    const filters = generateFiltersForSharingTask(createdReport.internal_id);
    const task = {
      task_filters: JSON.stringify(filters),
      task_excluded_ids: [],
      task_order_mode: 'asc',
      actions: [{ type: 'SHARE', context: { values: [TEST_ORGANIZATION.id] } }],
      scope: 'KNOWLEDGE',
    };
    const elements: BasicStoreEntity[] = [];
    await taskQuery(testContext, ADMIN_USER, task, 'KNOWLEDGE_CHANGE', (results: BasicStoreEntity[]) => {
      elements.push(...results);
    });
    const observableOrder1: BasicStoreEntity = elements[0];
    const observableOrder2: BasicStoreEntity = elements[1];
    expect(observableOrder1.created_at < observableOrder2.created_at);
  });

  it('When order mode is not set, default desc should be taken', async () => {
    const filters = generateFiltersForSharingTask(createdReport.internal_id);
    const task = {
      task_filters: JSON.stringify(filters),
      task_excluded_ids: [],
      actions: [{ type: 'SHARE', context: { values: [TEST_ORGANIZATION.id] } }],
      scope: 'KNOWLEDGE',
    };
    const elements: BasicStoreEntity[] = [];
    await taskQuery(testContext, ADMIN_USER, task, 'KNOWLEDGE_CHANGE', (results: BasicStoreEntity[]) => {
      elements.push(...results);
    });
    const observableOrder1: BasicStoreEntity = elements[0];
    const observableOrder2: BasicStoreEntity = elements[1];
    expect(observableOrder1.created_at > observableOrder2.created_at);
  });
});
