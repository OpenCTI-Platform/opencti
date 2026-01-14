import { describe, it, expect } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { type SingleSignMigrationInput, type SingleSignOnAddInput, type SingleSignOnMigrationResult, StrategyType } from '../../../src/generated/graphql';
import { USER_PARTICIPATE, USER_SECURITY } from '../../utils/testQuery';

export const SINGLE_SIGN_ON_LIST_QUERY = gql`
    query singleSignOns($first: Int) {
        singleSignOns(first: $first) {
            edges {
                node {
                    id
                    name
                    strategy
                    enabled
                }
            }
        }
    }
`;
export const SINGLE_SIGN_ON_CREATE = gql`
    mutation singleSignOnAdd($input: SingleSignOnAddInput!) {
        singleSignOnAdd(input: $input) {
            id
            name
            strategy
            enabled
        }
    }
`;
export const SINGLE_SIGN_ON_UPDATE = gql`
    mutation singleSignOnFieldPatch($id: ID!, $input: [EditInput!]!) {
        singleSignOnFieldPatch(id: $id, input: $input) {
            id
            name
            strategy
            enabled
          groups_management {
            groups_path
            groups_mapping
          }
        }
    }
`;
export const SINGLE_SIGN_ON_DELETE = gql`
    mutation singleSignOnDelete($id: ID!) {
        singleSignOnDelete(id: $id)
    }
`;

describe('Single Sign On', () => {
  let createdSingleSignOn1Id: string;
  let createdSingleSignOn2Id: string;
  const createdSingleSighOns: string[] = [];

  describe('Create', async () => {
    const createInput: SingleSignOnAddInput = {
      name: 'test name 1',
      strategy: StrategyType.SamlStrategy,
      enabled: true,
      identifier: 'test1',
      configuration: [
        { key: 'callbackUrl', value: 'http://myopencti/auth/samlTestDomain/callback', type: 'string' },
        { key: 'idpCert', value: '21341234', type: 'string' },
        { key: 'issuer', value: 'issuer', type: 'string' },
      ],
    };
    it('should not create single sign on entity without SETAUTH capa', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
        query: SINGLE_SIGN_ON_CREATE,
        variables: { input: createInput },
      });
    });
    it('should create single sign on entity with SETAUTH capa', async () => {
      const singleSignOn = await queryAsUserWithSuccess(USER_SECURITY.client, {
        query: SINGLE_SIGN_ON_CREATE,
        variables: { input: createInput },
      });

      expect(singleSignOn).toBeDefined();
      expect(singleSignOn?.data?.singleSignOnAdd.name).toBe('test name 1');
      createdSingleSignOn1Id = singleSignOn?.data?.singleSignOnAdd.id;
      createdSingleSighOns.push(createdSingleSignOn1Id);
    });
    it('should create another single sign on entity', async () => {
      const createInput2: SingleSignOnAddInput = {
        name: 'test name 2',
        strategy: StrategyType.OpenIdConnectStrategy,
        enabled: false,
        identifier: 'test2',
      };
      const singleSignOn2 = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_CREATE,
        variables: { input: createInput2 },
      });

      expect(singleSignOn2).toBeDefined();
      expect(singleSignOn2?.data?.singleSignOnAdd.name).toBe('test name 2');
      createdSingleSignOn2Id = singleSignOn2?.data?.singleSignOnAdd.id;
      createdSingleSighOns.push(createdSingleSignOn2Id);
    });
  });
  describe('Find List', () => {
    it('should not list single sign on without SETAUTH capa', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
        query: SINGLE_SIGN_ON_LIST_QUERY,
        variables: { first: 10 },
      });
    });
    it('should list single sign on', async () => {
      const singleSignOnList = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_LIST_QUERY,
        variables: { first: 10 },
      });

      expect(singleSignOnList).toBeDefined();

      const ssoList = singleSignOnList?.data?.singleSignOns.edges;
      const test1SSOEntity = ssoList.find((item: any) => item.node.id === createdSingleSignOn1Id);
      expect(test1SSOEntity?.node?.name).toBe('test name 1');
      const test2SSOEntity = ssoList.find((item: any) => item.node.id === createdSingleSignOn2Id);
      expect(test2SSOEntity?.node?.name).toBe('test name 2');
    });
  });
  describe('Update', () => {
    it('should not edit single sign on without SETAUTH capa', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
        query: SINGLE_SIGN_ON_UPDATE,
        variables: {
          id: createdSingleSignOn1Id,
          input: { key: 'name', value: 'updated name 1' },
        },
      });
    });
    it('should edit single sign on entity', async () => {
      const result = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_UPDATE,
        variables: {
          id: createdSingleSignOn1Id,
          input: { key: 'name', value: 'updated name 1' },
        },
      });

      expect(result?.data?.singleSignOnFieldPatch).toBeDefined();
      expect(result?.data?.singleSignOnFieldPatch?.name).toBe('updated name 1');
    });
    it('should edit single sign on entity with group management', async () => {
      const result = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_UPDATE,
        variables: {
          id: createdSingleSignOn1Id,
          input: { key: 'groups_management', value: [{
            groups_path: ['member'],
            groups_mapping: [
              '/Connector:Connectors',
            ],
          }] },
        },
      });
      expect(result?.data?.singleSignOnFieldPatch).toBeDefined();
      expect(result?.data?.singleSignOnFieldPatch?.groups_management.groups_path).toStrictEqual(['member']);
      expect(result?.data?.singleSignOnFieldPatch?.groups_management.groups_mapping).toStrictEqual(['/Connector:Connectors']);
    });
  });
  describe('Delete', () => {
    it('should not delete single sign on without SETAUTH capa', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
        query: SINGLE_SIGN_ON_DELETE,
        variables: { id: createdSingleSignOn1Id },
      });
    });
    it('should delete all single sign on entities', async () => {
      for (let i = 0; i < createdSingleSighOns.length; i += 1) {
        await queryAsAdminWithSuccess({
          query: SINGLE_SIGN_ON_DELETE,
          variables: { id: createdSingleSighOns[i] },
        });
      }
      const singleSignOnList = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_LIST_QUERY,
        variables: { first: 10 },
      });

      expect(singleSignOnList).toBeDefined();
      const ssoList = singleSignOnList?.data?.singleSignOns.edges;
      expect(ssoList.find((item: any) => item?.node?.id === createdSingleSignOn1Id)).toBeUndefined();
      expect(ssoList.find((item: any) => item?.node?.id === createdSingleSignOn2Id)).toBeUndefined();
    });
  });

  describe('configuration migration coverage', async () => {
    it('should migration dry run not raise errors', async () => {
      const input: SingleSignMigrationInput = {
        dry_run: true,
      };
      const result = await queryAsAdminWithSuccess({
        query: gql`
            mutation singleSignOnRunMigration($input: SingleSignMigrationInput!) {
                singleSignOnRunMigration(input: $input) {
                    name
                    description
                }
            }
        `,
        variables: { input },
      });
      expect(result?.data?.singleSignOnRunMigration).toBeDefined();
      const ssoConfig: SingleSignOnMigrationResult[] = result?.data?.singleSignOnRunMigration;
      expect(ssoConfig[0]?.description).toMatch(/Automatically detected from local */);
    });
  });
});
