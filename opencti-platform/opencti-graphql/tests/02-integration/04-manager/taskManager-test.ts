import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { BasicStoreEntity } from '../../../src/types/store';
import { addIndicator, promoteIndicatorToObservables } from '../../../src/modules/indicator/indicator-domain';
import { addStixCyberObservable, promoteObservableToIndicator, stixCyberObservableDelete } from '../../../src/domain/stixCyberObservable';
import { executePromoteIndicatorToObservables, executePromoteObservableToIndicator, executeReplace, executeRemoveAuthMembers } from '../../../src/manager/taskManager';
import type { AuthContext } from '../../../src/types/user';
import { ADMIN_USER, getUserIdByEmail, TEST_ORGANIZATION, testContext, USER_EDITOR } from '../../utils/testQuery';
import { MARKING_TLP_AMBER, MARKING_TLP_CLEAR } from '../../../src/schema/identifier';
import { addReport, findById as findReportById } from '../../../src/domain/report';
import { findById as findMarkingById } from '../../../src/domain/markingDefinition';
import { addOrganization, findById as findOrganizationById } from '../../../src/modules/organization/organization-domain';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { type OrganizationAddInput } from '../../../src/generated/graphql';
import { RELATION_OBJECT } from '../../../src/schema/stixRefRelationship';
import { promoteObservableInput, promoteIndicatorInput, promoteReportInput } from './taskManager-promote-values/promoteValues';
import { editAuthorizedMembers } from '../../../src/utils/authorizedMembers';
import { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../src/utils/access';

describe('TaskManager executeReplace tests ', () => {
  const adminContext: AuthContext = { user: ADMIN_USER, tracing: undefined, source: 'taskManager-integration-test', otp_mandatory: false };
  const reportsId: string[] = [];
  afterAll(async () => {
    expect(reportsId.length).toBe(9);
    for (let index = 0; index < reportsId.length; index += 1) {
      await stixDomainObjectDelete(adminContext, adminContext.user, reportsId[index]);
      const report = await findReportById(adminContext, adminContext.user, reportsId[index]);
      expect(report).toBeUndefined();
    }
  });
  describe('REPLACE objectMarking ', () => {
    it('REPLACE report marking with different marking', async () => {
      const reportInput = {
        name: 'test report marking with different marking',
        published: '2022-10-06T22:00:00.000Z',
        objectMarking: [MARKING_TLP_CLEAR],
      };
      const report = await addReport(adminContext, adminContext.user, reportInput);

      expect(report.id).toBeDefined();
      reportsId.push(report.id);
      const reportId = report.id;
      const marking = await findMarkingById(adminContext, adminContext.user, MARKING_TLP_AMBER);

      const actionContext = {
        field: 'object-marking',
        type: 'RELATION',
        values: [marking.id]
      };

      await executeReplace(adminContext, adminContext.user, actionContext, report);
      const reportAfterReplace = await findReportById(adminContext, adminContext.user, reportId);

      const markings = reportAfterReplace['object-marking'];
      expect(markings?.length).toEqual(1);
      if (markings) {
        const markingEntity = await findMarkingById(adminContext, adminContext.user, markings[0]);
        expect(markingEntity.standard_id).toEqual(MARKING_TLP_AMBER);
      }
    });
    it('REPLACE report marking with same marking', async () => {
      const reportInput = {
        name: 'test report marking with same marking',
        published: '2022-10-06T22:00:00.000Z',
        objectMarking: [MARKING_TLP_CLEAR],
      };
      const report = await addReport(adminContext, adminContext.user, reportInput);
      expect(report.id).toBeDefined();
      reportsId.push(report.id);
      const reportId = report.id;

      const marking = await findMarkingById(adminContext, adminContext.user, MARKING_TLP_CLEAR);

      const actionContext = {
        field: 'object-marking',
        type: 'RELATION',
        values: [marking.id]
      };

      await executeReplace(adminContext, adminContext.user, actionContext, report);
      const reportAfterReplace = await findReportById(adminContext, adminContext.user, reportId);

      const markings = reportAfterReplace['object-marking'];
      expect(markings?.length).toEqual(1);
      if (markings) {
        const markingEntity = await findMarkingById(adminContext, adminContext.user, markings[0]);
        expect(markingEntity.standard_id).toEqual(MARKING_TLP_CLEAR);
      }
    });
    it('REPLACE report without marking with marking', async () => {
      const reportInput = {
        name: 'test report no marking with marking',
        published: '2022-10-06T22:00:00.000Z',
        objectMarking: [],
      };
      const report = await addReport(adminContext, adminContext.user, reportInput);
      expect(report.id).toBeDefined();
      reportsId.push(report.id);
      const reportId = report.id;

      const marking = await findMarkingById(adminContext, adminContext.user, MARKING_TLP_CLEAR);

      const actionContext = {
        field: 'object-marking',
        type: 'RELATION',
        values: [marking.id]
      };

      await executeReplace(adminContext, adminContext.user, actionContext, report);
      const reportAfterReplace = await findReportById(adminContext, adminContext.user, reportId);

      const markings = reportAfterReplace['object-marking'];
      expect(markings?.length).toEqual(1);
      if (markings) {
        const markingEntity = await findMarkingById(adminContext, adminContext.user, markings[0]);
        expect(markingEntity.standard_id).toEqual(MARKING_TLP_CLEAR);
      }
    });
  });
  describe('REPLACE createdBy ', () => {
    let newOrganizationId: string;
    it('Create a new organisation', async () => {
      const orgInput: OrganizationAddInput = {
        name: 'Temporary org for tests',
      };
      const createdOrg = await addOrganization(adminContext, ADMIN_USER, orgInput);
      newOrganizationId = createdOrg.id;
    });

    it('REPLACE report author with different author', async () => {
      const reportInput = {
        name: 'test replace report author with different author',
        published: '2022-10-06T22:00:00.000Z',
        createdBy: TEST_ORGANIZATION.id,
      };
      const report = await addReport(adminContext, adminContext.user, reportInput);
      expect(report.id).toBeDefined();
      reportsId.push(report.id);
      const reportId = report.id;

      const actionContext = {
        field: 'created-by',
        type: 'RELATION',
        values: [newOrganizationId]
      };

      await executeReplace(adminContext, adminContext.user, actionContext, report);

      const { 'created-by': authorId } = await findReportById(adminContext, adminContext.user, reportId);
      if (authorId) {
        expect(authorId).toEqual(newOrganizationId);
      }
    });
    it('REPLACE report author with same author', async () => {
      const reportInput = {
        name: 'test replace report author with same author',
        published: '2022-10-06T22:00:00.000Z',
        createdBy: TEST_ORGANIZATION.id,
      };
      const report = await addReport(adminContext, adminContext.user, reportInput);
      expect(report.id).toBeDefined();
      reportsId.push(report.id);
      const reportId = report.id;

      const organization = await findOrganizationById(adminContext, ADMIN_USER, TEST_ORGANIZATION.id);

      const actionContext = {
        field: 'created-by',
        type: 'RELATION',
        values: [organization.id]
      };

      await executeReplace(adminContext, adminContext.user, actionContext, report);

      const { 'created-by': authorId } = await findReportById(adminContext, adminContext.user, reportId);
      if (authorId) {
        expect(authorId).toEqual(organization.id);
      }
    });
    it('REPLACE report without author with author', async () => {
      const reportInput = {
        name: 'test replace report without author with author',
        published: '2022-10-06T22:00:00.000Z',
        createdBy: '',
      };
      const report = await addReport(adminContext, adminContext.user, reportInput);
      expect(report.id).toBeDefined();
      reportsId.push(report.id);
      const reportId = report.id;

      const organization = await findOrganizationById(adminContext, ADMIN_USER, TEST_ORGANIZATION.id);

      const actionContext = {
        field: 'created-by',
        type: 'RELATION',
        values: [organization.id]
      };

      await executeReplace(adminContext, adminContext.user, actionContext, report);
      const { 'created-by': authorId } = await findReportById(adminContext, ADMIN_USER, reportId);
      if (authorId) {
        expect(authorId).toEqual(organization.id);
      }
    });

    it('Delete the new organisation', async () => {
      await stixDomainObjectDelete(adminContext, ADMIN_USER, newOrganizationId);
    });
  });
  describe('REPLACE description ', () => {
    it('REPLACE report description with different description', async () => {
      const reportInput = {
        name: 'test replace report description with different description',
        published: '2022-10-06T22:00:00.000Z',
        description: 'description',
      };
      const report = await addReport(adminContext, adminContext.user, reportInput);

      expect(report.id).toBeDefined();
      reportsId.push(report.id);
      const reportId = report.id;

      const actionContext = {
        field: 'description',
        type: 'ATTRIBUTE',
        values: ['new description']
      };

      await executeReplace(adminContext, adminContext.user, actionContext, report);
      const reportAfterReplace = await findReportById(adminContext, adminContext.user, reportId);

      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error
      const { description } = reportAfterReplace;
      if (description) {
        expect(description).toEqual('new description');
      }
    });
    it('REPLACE report description with same description', async () => {
      const reportInput = {
        name: 'test replace report description with same description',
        published: '2022-10-06T22:00:00.000Z',
        description: 'description',
      };
      const report = await addReport(adminContext, adminContext.user, reportInput);
      expect(report.id).toBeDefined();
      reportsId.push(report.id);
      const reportId = report.id;

      const actionContext = {
        field: 'description',
        type: 'ATTRIBUTE',
        values: ['description']
      };

      await executeReplace(adminContext, adminContext.user, actionContext, report);
      const reportAfterReplace = await findReportById(adminContext, adminContext.user, reportId);

      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error
      const { description } = reportAfterReplace;
      if (description) {
        expect(description).toEqual('description');
      }
    });
    it('REPLACE report without description with description', async () => {
      const reportInput = {
        name: 'test replace report without description with description',
        published: '2022-10-06T22:00:00.000Z',
        description: '',
      };
      const report = await addReport(adminContext, adminContext.user, reportInput);
      expect(report.id).toBeDefined();
      reportsId.push(report.id);
      const reportId = report.id;

      const actionContext = {
        field: 'description',
        type: 'ATTRIBUTE',
        values: ['description']
      };

      await executeReplace(adminContext, adminContext.user, actionContext, report);
      const reportAfterReplace = await findReportById(adminContext, adminContext.user, reportId);

      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error
      const { description } = reportAfterReplace;
      if (description) {
        expect(description).toEqual('description');
      }
    });
  });
});

describe('TaskManager executePromote tests', () => {
  const prepareTestContext = async () => {
    const createdIndicator = await addIndicator(testContext, ADMIN_USER, promoteIndicatorInput);
    const createObservable = await addStixCyberObservable(testContext, ADMIN_USER, promoteObservableInput);
    const createdReport = await addReport(testContext, ADMIN_USER, { ...promoteReportInput, objects: [createObservable.id, createdIndicator.id] });
    return { createdIndicator, createObservable, createdReport };
  };

  const resetTestContext = async (stixCyberObservableIds: string[], stixDomainObjectIds: string[]) => {
    for (let i = 0; i < stixCyberObservableIds.length; i += 1) {
      await stixCyberObservableDelete(testContext, ADMIN_USER, stixCyberObservableIds[i]);
    }
    for (let i = 0; i < stixDomainObjectIds.length; i += 1) {
      await stixDomainObjectDelete(testContext, ADMIN_USER, stixDomainObjectIds[i]);
    }
  };

  describe('PROMOTE IN CONTAINER', () => {
    let reportObjectCount = 0;
    let indicatorId = '';
    let observableId = '';
    let containerId = '';

    beforeAll(async () => {
      const { createdIndicator, createObservable, createdReport } = await prepareTestContext();

      indicatorId = createdIndicator.id;
      observableId = createObservable.id;
      containerId = createdReport.id;

      reportObjectCount = createdReport[RELATION_OBJECT].length;
    });

    afterAll(async () => {
      await resetTestContext([observableId], [indicatorId, containerId]);
    });

    it('PROMOTE indicator to observable', async () => {
      await executePromoteIndicatorToObservables(testContext, ADMIN_USER, { internal_id: indicatorId }, containerId);
      const report = await findReportById(testContext, ADMIN_USER, containerId) as BasicStoreEntity;
      expect(report[RELATION_OBJECT].length).greaterThan(reportObjectCount);
    });

    it('PROMOTE observable to indicator', async () => {
      await executePromoteObservableToIndicator(testContext, ADMIN_USER, { internal_id: observableId }, containerId);
      const report = await findReportById(testContext, ADMIN_USER, containerId) as BasicStoreEntity;
      expect(report[RELATION_OBJECT].length).greaterThan(reportObjectCount);
    });
  });

  describe('PROMOTE', () => {
    let indicatorId = '';
    let observableId = '';
    let containerId = '';
    let createdIndicatorId = '';
    let createdObservableId: string[] = [];

    beforeAll(async () => {
      const { createdIndicator, createObservable, createdReport } = await prepareTestContext();

      indicatorId = createdIndicator.id;
      observableId = createObservable.id;
      containerId = createdReport.id;
    });

    afterAll(async () => {
      await resetTestContext([observableId, ...createdObservableId], [indicatorId, createdIndicatorId, containerId]);
    });

    it('PROMOTE observable to indicator', async () => {
      const createdIndicator = await promoteObservableToIndicator(testContext, ADMIN_USER, observableId);
      expect(createdIndicator).not.toBeUndefined();
      createdIndicatorId = createdIndicator.id;
    });

    it('PROMOTE indicator to observable', async () => {
      const createdObservables = await promoteIndicatorToObservables(testContext, ADMIN_USER, indicatorId);
      expect(createdObservables.length).greaterThan(0);
      createdObservableId = createdObservables.map(({ id }) => id);
    });
  });
});

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
