import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getOrganizationIdByName, PLATFORM_ORGANIZATION, TEST_ORGANIZATION, testContext, USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdminWithSuccess, awaitUntilCondition, unSetOrganization, setOrganization, queryAsUserIsExpectedError, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { findById } from '../../../src/domain/report';
import { addReport } from '../../../src/domain/report';
import { addMalware } from '../../../src/domain/malware';
import { addCity } from '../../../src/domain/city';
import { addIndicator } from '../../../src/modules/indicator/indicator-domain';
import { addSector } from '../../../src/domain/sector';
import { addOrganization } from '../../../src/modules/organization/organization-domain';
import { addSystem } from '../../../src/domain/system';
import { addIndividual } from '../../../src/domain/individual';
import { addStixCyberObservable } from '../../../src/domain/stixCyberObservable';

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

describe('oganization-sharing-test', () => {
  describe('Database provision', () => {
    it('Should create test entities directly', async () => {
      // Create observable: Email-Addr
      const emailAddr = await addStixCyberObservable(testContext, ADMIN_USER, {
        type: 'Email-Addr',
        EmailAddr: { value: 'mail@mail.com' },
        x_opencti_score: 50,
        stix_id: 'email-addr--4879e703-0b80-52b8-983c-fc87774643c9',
      });

      // Create Malware
      const malware = await addMalware(testContext, ADMIN_USER, {
        name: 'Malware test',
        is_family: false,
        confidence: 100,
        stix_id: 'malware--d5c2c089-04db-5e3a-a694-62e266b14fef',
      });

      // Create City
      const city = await addCity(testContext, ADMIN_USER, {
        name: 'City test',
        confidence: 100,
        stix_id: 'location--d1693b3f-fcd4-5996-aede-f78d1144c1ce',
      });

      // Create Indicator
      const indicator = await addIndicator(testContext, ADMIN_USER, {
        name: 'Indicator test',
        pattern_type: 'stix',
        pattern: "[ipv4-addr:value = '185.158.114.133']",
        x_opencti_main_observable_type: 'IPv4-Addr',
        confidence: 100,
        x_opencti_score: 50,
        x_opencti_detection: false,
        valid_from: '2024-10-03T09:16:33.246Z',
        valid_until: '2024-10-23T14:51:12.680Z',
        stix_id: 'indicator--0001a19f-b9b0-5250-9696-6caa8676b867',
      });

      // Create Sector
      const sector = await addSector(testContext, ADMIN_USER, {
        name: 'sectorTest',
        confidence: 100,
        stix_id: 'identity--efcffe42-72f2-59ef-a0db-8c532f716dbe',
      });

      // Create Organization
      const organization = await addOrganization(testContext, ADMIN_USER, {
        name: 'organizationTest',
        confidence: 100,
        stix_id: 'identity--05c082f1-f7d5-59e5-8c99-2e5c7b8685bd',
      });

      // Create System
      const system = await addSystem(testContext, ADMIN_USER, {
        name: 'systemTest',
        confidence: 100,
        stix_id: 'identity--bb20232a-5a0a-59fa-85ae-ffb4eabef6a8',
      });

      // Create Individual
      const individual = await addIndividual(testContext, ADMIN_USER, {
        name: 'individualTest',
        confidence: 100,
        stix_id: 'identity--9e5e6cbd-570d-5c0f-a587-3eb6c1e8aaff',
      });

      // Create Report with all objects
      const report = await addReport(testContext, ADMIN_USER, {
        name: 'Report to share',
        published: '2024-10-03T08:04:39.000Z',
        confidence: 100,
        objects: [
          emailAddr.id,
          malware.id,
          city.id,
          indicator.id,
          sector.id,
          organization.id,
          system.id,
          individual.id,
        ],
        stix_id: 'report--ce32448d-733b-5e34-ac4f-2759ce5db1ae',
      });

      expect(report).not.toBeNull();
      expect(report.name).toEqual('Report to share');
    });
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
      await setOrganization(PLATFORM_ORGANIZATION);
    });
    it('should not delete organization if platform organization', async () => {
      const DELETE_QUERY = gql`
        mutation organizationDelete($id: ID!) {
          organizationDelete(id: $id)
        }
      `;
      // Delete the organization should fail with error
      await queryAsUserIsExpectedError(USER_EDITOR, {
        query: DELETE_QUERY,
        variables: { id: PLATFORM_ORGANIZATION.id },
      }, 'Cannot delete the platform organization.', 'FUNCTIONAL_ERROR');
    });
    it('should user from different organization not access the report', async () => {
      const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
        query: REPORT_STIX_DOMAIN_ENTITIES,
        variables: { id: reportInternalId },
      });
      expect(queryResult.data?.report).toBeNull();
    });

    // If this test fails, please check that one worker is running.
    it('should share Report with Organization - WORKER REQUIRED', async () => {
      // Get organization id
      organizationId = await getOrganizationIdByName(TEST_ORGANIZATION.name);
      const organizationSharingQueryResult = await queryAsAdminWithSuccess({
        query: ORGANIZATION_SHARING_QUERY,
        variables: { id: reportInternalId, organizationId },
      });
      expect(organizationSharingQueryResult?.data?.stixCoreObjectEdit.restrictionOrganizationAdd).not.toBeNull();
    });
    it('should Editor user access all objects', async () => {
      const condition = async () => {
        const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
          query: REPORT_STIX_DOMAIN_ENTITIES,
          variables: { id: reportInternalId },
        });
        return queryResult.data?.report !== null && queryResult.data?.report.objects.edges.length === 8;
      };
      // wait for task manager & worker to handle organization sharing
      await awaitUntilCondition(condition, 1000, 10, true, 'Please check that you have a test worker running');
      const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
        query: REPORT_STIX_DOMAIN_ENTITIES,
        variables: { id: reportInternalId },
      });
      expect(queryResult.data?.report.objects.edges.length).toEqual(8);
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
      const purgeQueryResult = await queryAsAdminWithSuccess({
        query: PURGE_QUERY,
        variables: {
          id: reportInternalId,
          purgeElements: true,
        },
      });
      expect(purgeQueryResult.data?.reportEdit.delete).toEqual(reportInternalId);
    });
    it('should plateform organization sharing and EE deactivated', async () => {
      await unSetOrganization();
    });
  });
});
