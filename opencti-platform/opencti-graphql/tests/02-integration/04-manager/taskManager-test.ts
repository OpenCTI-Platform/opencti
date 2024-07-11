import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addIndicator, promoteIndicatorToObservables } from '../../../src/modules/indicator/indicator-domain';
import { addStixCyberObservable, promoteObservableToIndicator, stixCyberObservableDelete } from '../../../src/domain/stixCyberObservable';
import { executePromoteIndicatorToObservables, executePromoteObservableToIndicator, executeReplace } from '../../../src/manager/taskManager';
import type { AuthContext } from '../../../src/types/user';
import { ADMIN_USER, TEST_ORGANIZATION, testContext } from '../../utils/testQuery';
import { MARKING_TLP_AMBER, MARKING_TLP_CLEAR } from '../../../src/schema/identifier';
import { addReport, findById as findReportById } from '../../../src/domain/report';
import { findById as findMarkingById } from '../../../src/domain/markingDefinition';
import { addOrganization, findById as findOrganizationById } from '../../../src/modules/organization/organization-domain';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { type OrganizationAddInput } from '../../../src/generated/graphql';
import { promoteObservableInput, promoteIndicatorInput, promoteReportInput } from './taskManager-promote-values/promoteValues';

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
    let indicatorId = '';
    let observableId = '';
    let containerId = '';

    beforeAll(async () => {
      const { createdIndicator, createObservable, createdReport } = await prepareTestContext();

      indicatorId = createdIndicator.id;
      observableId = createObservable.id;
      containerId = createdReport.id;
    });

    afterAll(async () => {
      await resetTestContext([observableId], [indicatorId, containerId]);
    });

    it('PROMOTE indicator to observable', async () => {
      const { observables, relations } = await executePromoteIndicatorToObservables(testContext, ADMIN_USER, { internal_id: indicatorId }, containerId);
      expect(observables.length).toEqual(1);
      expect(relations.length).toEqual(1);
    });

    it('PROMOTE observable to indicator', async () => {
      const { indicators, relations } = await executePromoteObservableToIndicator(testContext, ADMIN_USER, { internal_id: observableId }, containerId);
      expect(indicators.length).toEqual(1);
      expect(relations.length).toEqual(1);
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
