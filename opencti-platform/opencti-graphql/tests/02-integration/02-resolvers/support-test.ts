import { describe, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

describe('SupportPackage resolver standard behavior', () => {
  it('should support package be created', async () => {
    const CREATE_QUERY = gql`
          mutation supportPackageAdd($input: SupportPackageAddInput!) {
              supportPackageAdd(input: $input) {
                  id
              }
          }
      `;

    const PACKAGE_TO_CREATE = {
      input: {
        name: 'Support package for test.',
      },
    };
    const supportPackageCreationResponse = await queryAsAdminWithSuccess({
      query: CREATE_QUERY,
      variables: PACKAGE_TO_CREATE,
    });

    console.log('supportPackageCreationResponse', supportPackageCreationResponse);
  });
});
