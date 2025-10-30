import { afterAll, describe, expect, it } from 'vitest';
import type { AuthContext } from '../../../src/types/user';
import { ADMIN_USER, getUserIdByEmail, USER_EDITOR } from '../../utils/testQuery';
import { addReport, findById as findReportById } from '../../../src/domain/report';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { editAuthorizedMembers } from '../../../src/utils/authorizedMembers';
import { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../src/utils/access';
import { executeRemoveAuthMembers } from '../../../src/domain/stixCoreObject';

describe('TaskManager executeRemoveAuthMembers tests', () => {
  const adminContext: AuthContext = {
    user: ADMIN_USER,
    tracing: undefined,
    source: 'taskManager-integration-test',
    otp_mandatory: false,
    user_inside_platform_organization: false,
    sharedData: {},
  };
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
    expect(reportWithAuthorizedMembers.restricted_members).toEqual([
      {
        id: userEditorId,
        access_right: 'admin'
      }
    ]);

    // Admin user removes authorized members: + 1 update
    await executeRemoveAuthMembers(adminContext, adminContext.user, report);

    // Verify there are no authorized
    const reportAfterRemove = await findReportById(adminContext, adminContext.user, reportId);
    expect(reportAfterRemove.restricted_members).toBeUndefined();
  });
});
