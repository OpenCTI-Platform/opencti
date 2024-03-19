import { afterAll, describe, expect, it } from 'vitest';
import { executeReplace } from '../../../src/manager/taskManager';
import type { AuthContext } from '../../../src/types/user';
import { ADMIN_USER } from '../../utils/testQuery';
import { MARKING_TLP_CLEAR, MARKING_TLP_AMBER } from '../../../src/schema/identifier';
import { addReport, findById as findReportById } from '../../../src/domain/report';
import { findById } from '../../../src/domain/markingDefinition';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';

describe('TaskManager executeReplace tests ', () => {
  const adminContext: AuthContext = { user: ADMIN_USER, tracing: undefined, source: 'taskManager-integration-test', otp_mandatory: false };
  const reportsId: string[] = [];
  afterAll(async () => {
    expect(reportsId.length).toBe(3);
    for (let index = 0; index < reportsId.length; index += 1) {
      await stixDomainObjectDelete(adminContext, adminContext.user, reportsId[index]);
      const report = await findReportById(adminContext, adminContext.user, reportsId[index]);
      expect(report).toBeUndefined();
    }
  });
  it('REPLACE report marking with different marking', async () => {
    const reportInput = {
      name: 'test report marking with different marking',
      objectMarking: [MARKING_TLP_CLEAR],
    };
    const report = await addReport(adminContext, adminContext.user, reportInput);

    expect(report.id).toBeDefined();
    reportsId.push(report.id);
    const reportId = report.id;
    const marking = await findById(adminContext, adminContext.user, MARKING_TLP_AMBER);

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
      const markingEntity = await findById(adminContext, adminContext.user, markings[0]);
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

    const marking = await findById(adminContext, adminContext.user, MARKING_TLP_CLEAR);

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
      const markingEntity = await findById(adminContext, adminContext.user, markings[0]);
      expect(markingEntity.standard_id).toEqual(MARKING_TLP_CLEAR);
    }
  });
  it('REPLACE report no marking with marking', async () => {
    const reportInput = {
      name: 'test report no marking with marking',
      objectMarking: [],
    };
    const report = await addReport(adminContext, adminContext.user, reportInput);
    expect(report.id).toBeDefined();
    reportsId.push(report.id);
    const reportId = report.id;

    const marking = await findById(adminContext, adminContext.user, MARKING_TLP_CLEAR);

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
      const markingEntity = await findById(adminContext, adminContext.user, markings[0]);
      expect(markingEntity.standard_id).toEqual(MARKING_TLP_CLEAR);
    }
  });
});
