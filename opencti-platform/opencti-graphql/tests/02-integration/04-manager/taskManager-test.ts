import { afterAll, describe, expect, it } from 'vitest';
import { executeReplace } from '../../../src/manager/taskManager';
import type { AuthContext } from '../../../src/types/user';
import { ADMIN_USER, TEST_ORGANIZATION } from '../../utils/testQuery';
import { MARKING_TLP_CLEAR, MARKING_TLP_AMBER } from '../../../src/schema/identifier';
import { addReport, findById as findReportById } from '../../../src/domain/report';
import { findById as findMarkingById } from '../../../src/domain/markingDefinition';
import { addOrganization, findById as findOrganizationById } from '../../../src/modules/organization/organization-domain';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { type OrganizationAddInput } from '../../../src/generated/graphql';

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
