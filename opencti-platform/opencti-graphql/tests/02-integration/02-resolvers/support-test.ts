import { describe, it, expect } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, requestFileFromStorageAsAdmin } from '../../utils/testQueryHelper';
import { USER_PARTICIPATE } from '../../utils/testQuery';
import { wait } from '../../../src/database/utils';

const CREATE_QUERY = gql`
    mutation supportPackageAdd($input: SupportPackageAddInput!) {
        supportPackageAdd(input: $input) {
            id
            package_url
            package_status
        }
    }
`;

describe('SupportPackage resolver standard behavior', () => {
  let createdSupportPackageId: string = '';
  it('should support package be created', async () => {
    const supportPackageCreationResponse = await queryAsAdminWithSuccess({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: `support-file-${new Date().getTime()}`,
        },
      },
    });
    expect(supportPackageCreationResponse.data?.supportPackageAdd.id).toBeDefined();
    createdSupportPackageId = supportPackageCreationResponse.data?.supportPackageAdd.id;

    expect(supportPackageCreationResponse.data?.supportPackageAdd.package_url).toBeDefined();
  });

  it('should support package be force zipped', async () => {
    // Wait for pub/sub magic to happens
    await wait(3000);

    const FORCE_ZIP_QUERY = gql`
      mutation supportPackageForceZip($input: SupportPackageForceZipInput!) {
        supportPackageForceZip(input: $input) {
          id
          package_url
          package_status
        }
      }
    `;

    const supportPackageZipResponse = await queryAsAdminWithSuccess({
      query: FORCE_ZIP_QUERY,
      variables: {
        input: {
          id: createdSupportPackageId,
        },
      },
    });
    expect(supportPackageZipResponse.data?.supportPackageForceZip.id).toBeDefined();
    expect(supportPackageZipResponse.data?.supportPackageForceZip.package_url).toBeDefined();
    const result = await requestFileFromStorageAsAdmin(supportPackageZipResponse.data?.supportPackageForceZip.package_url);
    expect(result.toString().length).toBeGreaterThan(1);
    // expect no error throw, it means that zip exists in S3 storage and can be downloaded.
  });

  it('should support package be findById', async () => {
    const READ_QUERY = gql`
          query supportPackage($id: String!) {
              supportPackage(id: $id) {
                  id
                  standard_id
                  name
              }
          }
      `;

    const queryResult = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: { id: createdSupportPackageId } });
    expect(queryResult.data?.supportPackage.name).toBeDefined();
  });

  it('should list all support package', async () => {
    const LIST_QUERY = gql`
            query supportPackages(
                $first: Int
                $after: ID
                $orderBy: SupportPackageOrdering
                $orderMode: OrderingMode
                $filters: FilterGroup
                $search: String
            ) {
                supportPackages(
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
                            standard_id
                            name
                        }
                    }
                }
            }
        `;

    const queryResult = await queryAsAdminWithSuccess({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data?.supportPackages.edges.length).toBeGreaterThan(0);
  });
});

describe('SupportPackage rights management checks', () => {
  it('should Participant/Editor user not be allowed to create a DecayRule.', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
      query: CREATE_QUERY,
      variables: {
        input: {
          name: `support-file-${new Date().getTime()}`,
        },
      },
    });
  });
});
