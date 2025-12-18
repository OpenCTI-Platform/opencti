import { describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import {
  ADMIN_API_TOKEN,
  ADMIN_USER,
  API_URI,
  FIVE_MINUTES,
  getOrganizationIdByName,
  PLATFORM_ORGANIZATION,
  PYTHON_PATH,
  TEST_ORGANIZATION,
  testContext,
  USER_EDITOR,
} from '../../utils/testQuery';
import { adminQueryWithSuccess, awaitUntilCondition, unSetOrganization, setOrganization, queryAsUserIsExpectedError, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { findById } from '../../../src/domain/report';
import { execChildPython } from '../../../src/python/pythonBridge';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';

const ORGANIZATION_SHARING_QUERY = gql`
  mutation StixCoreObjectSharingGroupAddMutation(
    $id: ID!
    $organizationId: [ID!]!
  ) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationAdd(organizationId: $organizationId) {
        id
        objectOrganization {
          id
          name
        }
      }
    }
  }
`;

const REPORT_STIX_DOMAIN_ENTITIES = gql`
  query report($id: String!) {
    report(id: $id) {
      id
      standard_id
      objects(first: 30) {
        edges {
          node {
            ... on BasicObject {
              id
              standard_id
            }
            ... on BasicRelationship {
              id
              standard_id
            }
          }
        }
      }
    }
  }
`;

const importOpts: string[] = [API_URI, ADMIN_API_TOKEN, './tests/data/organization-sharing/20241003_Report_to_test_orga_sharing_full.json'];

describe('Database provision', () => {
  it('Should import creation succeed', async () => {
    // Inject data
    const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', importOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');
  }, FIVE_MINUTES);
  // Python lib is fixed but we need to wait for a new release
  it('Should import update succeed', async () => {
    const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', importOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');
  }, FIVE_MINUTES);
});

describe('Organization sharing standard behavior for container', () => {
  let reportInternalId: string;
  let organizationId: string;
  it('should load Report', async () => {
    const report = await findById(testContext, ADMIN_USER, 'report--ce32448d-733b-5e34-ac4f-2759ce5db1ae');
    expect(report).not.toBeUndefined();
    reportInternalId = report.id;
  });
  it('should platform organization sharing and EE activated', async () => {
    // Activate EE for this test
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    await setOrganization(PLATFORM_ORGANIZATION);
  });
  it('should not delete organization if platform organization', async () => {
    const DELETE_QUERY = gql`
      mutation organizationDelete($id: ID!) {
        organizationDelete(id: $id)
      }
    `;
    // Delete the organization should fail with error
    await queryAsUserIsExpectedError(USER_EDITOR.client, {
      query: DELETE_QUERY,
      variables: { id: PLATFORM_ORGANIZATION.id },
    }, 'Cannot delete the platform organization.', 'FUNCTIONAL_ERROR');
  });
  it('should user from different organization not access the report', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: REPORT_STIX_DOMAIN_ENTITIES,
      variables: { id: reportInternalId },
    });
    expect(queryResult.data.report).toBeNull();
  });

  // If this test fails, please check that one worker is running.
  it('should share Report with Organization - WORKER REQUIRED', async () => {
    // Get organization id
    organizationId = await getOrganizationIdByName(TEST_ORGANIZATION.name);
    const organizationSharingQueryResult = await adminQueryWithSuccess({
      query: ORGANIZATION_SHARING_QUERY,
      variables: { id: reportInternalId, organizationId },
    });
    expect(organizationSharingQueryResult?.data?.stixCoreObjectEdit.restrictionOrganizationAdd).not.toBeNull();
  });
  it('should Editor user access all objects', async () => {
    await awaitUntilCondition(async () => {
      const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
        query: REPORT_STIX_DOMAIN_ENTITIES,
        variables: { id: reportInternalId },
      });
      return queryResult.data.report !== null && queryResult.data.report.objects.edges.length === 8;
    }); // wait for task manager & worker to handle organization sharing
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: REPORT_STIX_DOMAIN_ENTITIES,
      variables: { id: reportInternalId },
    });
    expect(queryResult.data.report.objects.edges.length).toEqual(8);
  });
  it('should all entities deleted', async () => {
    const PURGE_QUERY = gql`
      mutation ReportPopoverDeletionMutation(
        $id: ID!
        $purgeElements: Boolean
      ) {
        reportEdit(id: $id) {
          delete(purgeElements: $purgeElements)
        }
      }
    `;
    const purgeQueryResult = await adminQueryWithSuccess({
      query: PURGE_QUERY,
      variables: {
        id: reportInternalId,
        purgeElements: true,
      },
    });
    expect(purgeQueryResult.data.reportEdit.delete).toEqual(reportInternalId);
  });
  it('should plateform organization sharing and EE deactivated', async () => {
    // Deactivate EE at the end of this test - back to CE
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockRejectedValue('Enterprise edition is not enabled');
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(false);
    await unSetOrganization();
  });
});
