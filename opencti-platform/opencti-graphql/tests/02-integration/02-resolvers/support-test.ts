import { describe, it, expect } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, requestFileFromStorageAsAdmin } from '../../utils/testQueryHelper';
import { ADMIN_USER, USER_DISINFORMATION_ANALYST, USER_PARTICIPATE } from '../../utils/testQuery';
import { wait } from '../../../src/database/utils';
import type { SupportPackage } from '../../../src/generated/graphql';
import { addSupportPackage } from '../../../src/modules/support/support-domain';
import convertSupportPackageToStix from '../../../src/modules/support/support-converter';
import type { StoreEntitySupportPackage } from '../../../src/modules/support/support-types';
import type { AuthContext } from '../../../src/types/user';

const CREATE_QUERY = gql`
    mutation supportPackageAdd($input: SupportPackageAddInput!) {
        supportPackageAdd(input: $input) {
            id
            package_url
            package_status
        }
    }
`;

const READ_QUERY = gql`
    query supportPackage($id: String!) {
        supportPackage(id: $id) {
            id
            standard_id
            name
            package_url
            package_status
        }
    }
`;

describe('SupportPackage resolver standard behavior', () => {
  let createdSupportPackage: SupportPackage;
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
    createdSupportPackage = supportPackageCreationResponse.data?.supportPackageAdd;

    expect(supportPackageCreationResponse.data?.supportPackageAdd.package_url).toBeDefined();
  });

  it('should support package be force zipped', async () => {
    // Wait for pub/sub magic to happens
    await wait(1000);

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
          id: createdSupportPackage.id,
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
    const queryResult = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: { id: createdSupportPackage.id } });
    expect(queryResult.data?.supportPackage.name).toBeDefined();
    expect(queryResult.data?.supportPackage.package_url).toBeDefined(); // after force zip, zip should exists
    createdSupportPackage = queryResult.data?.supportPackage;
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

  it('should delete support package by Id', async () => {
    const DELETE_QUERY = gql`
            mutation supportPackageDelete($id: ID!) {
                supportPackageDelete(id: $id)
            }
        `;

    const deleteQueryResult = await queryAsAdminWithSuccess({ query: DELETE_QUERY, variables: { id: createdSupportPackage.id } });
    expect(deleteQueryResult.data?.supportPackageDelete).toBeDefined();

    // Waiting for S3 storage to process delete.
    await wait(3000);

    const queryResult = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: { id: createdSupportPackage.id } });
    expect(queryResult.data?.supportPackage).toBeNull();

    // Check that files does not exist anymore on storage.
    expect(createdSupportPackage.package_url).toBeDefined();
    let gotFileStorageError = false;
    try {
      if (createdSupportPackage?.package_url) {
        await requestFileFromStorageAsAdmin(createdSupportPackage?.package_url);
      }
    } catch (e) {
      gotFileStorageError = true;
    } finally {
      expect(gotFileStorageError, 'We expect that the file cannot be found on storage anymore.').toBeTruthy();
    }
  });
});

describe('SupportPackage rights management checks', () => {
  it('should Participant/Editor user not be allowed to create a SupportPackage.', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
      query: CREATE_QUERY,
      variables: {
        input: {
          name: `support-file-${new Date().getTime()}`,
        },
      },
    });
  });

  it('Should Disinformation analyst user not be allowed to create a SupportPackage.', async () => {
    await queryAsUserIsExpectedForbidden(USER_DISINFORMATION_ANALYST.client, {
      query: CREATE_QUERY,
      variables: {
        input: {
          name: `support-file-${new Date().getTime()}`,
        },
      },
    });
  });
});

describe('Testing STIX conversion for the day when Internal object will be exported.', () => {
  const adminContext: AuthContext = { user: ADMIN_USER, tracing: undefined, source: 'supportPackageListener-test', otp_mandatory: false };
  it('should be STIX converted', async () => {
    const supportPackage = await addSupportPackage(adminContext, ADMIN_USER, { name: 'testing-stix-converter' });

    const stixResult = convertSupportPackageToStix(supportPackage as StoreEntitySupportPackage);
    expect(stixResult.id.startsWith('support-package--'), `${stixResult.id} does not start with support-package--`).toBeTruthy();
  });
});
