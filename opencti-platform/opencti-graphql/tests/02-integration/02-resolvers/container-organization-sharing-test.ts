import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import {
  ADMIN_API_TOKEN,
  ADMIN_USER,
  adminQuery,
  API_URI,
  FIVE_MINUTES,
  getOrganizationIdByName,
  PLATFORM_ORGANIZATION,
  PYTHON_PATH,
  TEST_ORGANIZATION,
  testContext,
  USER_EDITOR
} from '../../utils/testQuery';
import { adminQueryWithSuccess, enableCEAndUnSetOrganization, enableEEAndSetOrganization, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { findById } from '../../../src/domain/report';
import { taskHandler } from '../../../src/manager/taskManager';
import { execChildPython } from '../../../src/python/pythonBridge';

const READ_QUERY = gql`
  query caseIncident($id: String!) {
    caseIncident(id: $id) {
      id
      standard_id
      name
      authorized_members {
        id
        access_right
      }
      currentUserAccessRight
    }
  }
`;

const DELETE_QUERY = gql`
  mutation CaseIncidentDelete($id: ID!) {
    caseIncidentDelete(id: $id)
  }
`;

const ORGANIZATION_SHARING_QUERY = gql`
  mutation StixCoreObjectSharingGroupAddMutation(
    $id: ID!
    $organizationId: ID!
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

const importOpts: string[] = [API_URI, ADMIN_API_TOKEN, './tests/data/DATA-TEST-STIX2_v2.json'];

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
    const report = await findById(testContext, ADMIN_USER, 'report--57162a65-2a58-560b-9a65-47c3f040f3d4'); // Report is in DATA-TEST-STIX_v2.json
    reportInternalId = report.internal_id;
  });
  it('should platform organization sharing and EE activated', async () => {
    await enableEEAndSetOrganization(PLATFORM_ORGANIZATION);
  });
  it('should share Report with Organization', async () => {
    // Get organization id
    organizationId = await getOrganizationIdByName(TEST_ORGANIZATION.name);
    const organizationSharingQueryResult = await adminQueryWithSuccess({
      query: ORGANIZATION_SHARING_QUERY,
      variables: { id: reportInternalId, organizationId }
    });
    expect(organizationSharingQueryResult?.data?.stixCoreObjectEdit.restrictionOrganizationAdd).not.toBeNull();
    expect(organizationSharingQueryResult?.data?.stixCoreObjectEdit.restrictionOrganizationAdd.objectOrganization[0].name).toEqual(TEST_ORGANIZATION.name);

    // Need background task magic to happens for sharing
    await taskHandler();
  });
  it('should Editor user access all objects', async () => {
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
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: REPORT_STIX_DOMAIN_ENTITIES,
      variables: { id: reportInternalId },
    });
    expect(queryResult.data.report.objects.edges.length).toEqual(10);
  });
  it('should delete Report', async () => {
    // Delete the case
    await adminQuery({
      query: DELETE_QUERY,
      variables: { id: reportInternalId },
    });
    // Verify is no longer found
    const queryResult = await adminQueryWithSuccess({ query: READ_QUERY, variables: { id: reportInternalId } });
    expect(queryResult?.data?.caseIncident).toBeNull();
  });
  it('should plateform organization sharing and EE deactivated', async () => {
    await enableCEAndUnSetOrganization();
  });
});
