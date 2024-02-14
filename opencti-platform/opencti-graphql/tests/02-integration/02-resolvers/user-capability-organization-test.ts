import { describe, expect, it, afterAll } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getUserIdByEmail, queryAsAdmin, TEST_MAIN_ORGANIZATION, USER_ADMIN_EXT } from '../../utils/testQuery';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import type { BasicStoreEntityEdge } from '../../../src/types/store';
import type { BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';

let adminOfExternalOrgId = '';
let platformSettingsId = '';
let mainOrganisationId = '';
describe('User capacity verifications with organization setups', () => {
  it('should get the external org admin id', async () => {
    adminOfExternalOrgId = await getUserIdByEmail(USER_ADMIN_EXT.email);
    expect(adminOfExternalOrgId, 'External organization is not created, please check testQuery.').toBeDefined();
    expect(adminOfExternalOrgId.length, 'External organization is not created, please check testQuery.').toBeGreaterThan(0);

    console.log('adminOfExternalOrg', adminOfExternalOrgId);
    console.log('adminOfOrgId', ADMIN_USER.id);
  });

  it('should get the main organization id', async () => {
    const LIST_ORG_QUERY = gql`
            query organizations(
                $first: Int
                $after: ID
                $orderBy: OrganizationsOrdering
                $orderMode: OrderingMode
                $filters: FilterGroup
                $search: String
            ) {
                organizations(
                    first: $first
                    after: $after
                    orderBy: $orderBy
                    orderMode: $orderMode
                    filters: $filters
                    search: $search
                ) {
                    edges {
                        node {
                            id
                            name
                            description
                        }
                    }
                }
            }
        `;
    const orgListResult = await queryAsAdminWithSuccess({ query: LIST_ORG_QUERY, variables: { first: 10 } });
    const orgList: BasicStoreEntityEdge<BasicStoreEntityOrganization>[] = orgListResult.data?.organizations.edges;
    console.log('orgList', orgList);
    const mainOrganisations = orgList.filter((org: BasicStoreEntityEdge<BasicStoreEntityOrganization>) => {
      console.log('org:', org);
      return org.node.name === TEST_MAIN_ORGANIZATION.name;
    });
    mainOrganisationId = mainOrganisations[0].node.id;
  });

  it('should assign the main organization as platform organisation', async () => {
    const READ_SETTINGS_QUERY = gql`
            query settings {
                settings {
                    id
                    platform_title
                    platform_email
                    platform_language
                    platform_theme
                    platform_organization {
                        id
                    }
                }
            }
        `;
    const platformSettings = await queryAsAdminWithSuccess({ query: READ_SETTINGS_QUERY, variables: {} });
    console.log('platformSettings', platformSettings);
    expect(platformSettings.data?.settings.id).toBeDefined();
    if (platformSettings.data?.settings.id) {
      platformSettingsId = platformSettings.data.settings.id;
    }

    const PLATFORM_ORG_PATCH_QUERY = gql`
            mutation settingsEdit($id: ID!, $input: [EditInput!]!) {
                settingsEdit(id: $id) {
                    fieldPatch(input: $input) {
                        id
                    }
                }
            }
        `;

    await queryAsAdminWithSuccess({
      query: PLATFORM_ORG_PATCH_QUERY,
      variables: { id: platformSettingsId, input: { key: 'platform_organization', value: mainOrganisationId } },
    });

    const platformSettingsAfter = await queryAsAdminWithSuccess({ query: READ_SETTINGS_QUERY, variables: {} });
    console.log('platformSettingsAfter', platformSettingsAfter);
  });

  afterAll(async () => {
    console.log('CLEANUP');

    // Clean the platform organization settings
    const PLATFORM_ORG_PATCH_QUERY = gql`
            mutation settingsEdit($id: ID!, $input: [EditInput!]!) {
                settingsEdit(id: $id) {
                    fieldPatch(input: $input) {
                        id
                    }
                }
            }
        `;

    await queryAsAdmin({
      query: PLATFORM_ORG_PATCH_QUERY,
      variables: { id: platformSettingsId, input: { key: 'platform_organization', value: '' } },
    });
  });
});
