import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { BasicStoreEntity, StoreEntityReport } from '../../../src/types/store';
import { addIndicator, promoteIndicatorToObservables } from '../../../src/modules/indicator/indicator-domain';
import { addStixCyberObservable, promoteObservableToIndicator, stixCyberObservableDelete } from '../../../src/domain/stixCyberObservable';
import { computeQueryTaskElements, executePromoteIndicatorToObservables, executePromoteObservableToIndicator, executeReplace } from '../../../src/manager/taskManager';
import type { AuthContext } from '../../../src/types/user';
import { ADMIN_USER, TEST_ORGANIZATION, testContext } from '../../utils/testQuery';
import { MARKING_TLP_AMBER, MARKING_TLP_CLEAR } from '../../../src/schema/identifier';
import { addReport, findById as findReportById } from '../../../src/domain/report';
import { findById as findMarkingById } from '../../../src/domain/markingDefinition';
import { addOrganization, findById as findOrganizationById } from '../../../src/modules/organization/organization-domain';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { type OrganizationAddInput } from '../../../src/generated/graphql';
import { RELATION_OBJECT } from '../../../src/schema/stixRefRelationship';
import { promoteObservableInput, promoteIndicatorInput, promoteReportInput } from './taskManager-promote-values/promoteValues';
import { generateFiltersForSharingTask } from '../../../src/domain/stix';
import { addStixCoreRelationship } from '../../../src/domain/stixCoreRelationship';

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
    const { elements } = await computeQueryTaskElements(testContext, ADMIN_USER, task);
    const observableOrder1: BasicStoreEntity = elements[0].element;
    const observableOrder2: BasicStoreEntity = elements[1].element;
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
    const { elements } = await computeQueryTaskElements(testContext, ADMIN_USER, task);
    const observableOrder1: BasicStoreEntity = elements[0].element;
    const observableOrder2: BasicStoreEntity = elements[1].element;
    expect(observableOrder1.created_at > observableOrder2.created_at);
  });
});
