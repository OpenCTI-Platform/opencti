import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import {
  type ConfigurationTypeInput,
  type EditInput,
  EditOperation,
  FilterMode,
  FilterOperator,
  type SingleSignMigrationInput,
  type SingleSignOnAddInput,
  type SingleSignOnMigrationResult,
  StrategyType,
} from '../../../../src/generated/graphql';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedError, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER, testContext, USER_PARTICIPATE, USER_SECURITY } from '../../../utils/testQuery';
import { deleteElementById } from '../../../../src/database/middleware';
import { ENTITY_TYPE_SINGLE_SIGN_ON } from '../../../../src/modules/singleSignOn/singleSignOn-types';

export const SINGLE_SIGN_ON_LIST_QUERY = gql`
    query singleSignOns($first: Int $filters: FilterGroup) {
        singleSignOns(first: $first, filters: $filters) {
            edges {
                node {
                    id
                    name
                    strategy
                    enabled
                    identifier
                    configuration {
                        key
                        value
                        type
                    }
                    groups_management {
                        groups_path
                        groups_mapping
                    }
                    organizations_management {
                        organizations_mapping
                    }
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
            configuration {
                key
                value
                type
            }
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
            configuration {
                key
                value
                type
            }
          groups_management {
            groups_path
            groups_mapping
          }
          organizations_management {
              organizations_mapping
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
        { key: 'cert', value: '21341234', type: 'string' },
        { key: 'issuer', value: 'issuer', type: 'string' },
        { key: 'privateKey', value: 'myPK', type: 'string' },
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

      const configurationData: ConfigurationTypeInput[] = singleSignOn?.data?.singleSignOnAdd?.configuration as ConfigurationTypeInput[];
      const certData = configurationData.find((config) => config.key === 'cert') as ConfigurationTypeInput;
      expect(certData.value).toBe('21341234');
      const callbackUrlData = configurationData.find((config) => config.key === 'callbackUrl') as ConfigurationTypeInput;
      expect(callbackUrlData.value).toBe('http://myopencti/auth/samlTestDomain/callback');
      const issuerData = configurationData.find((config) => config.key === 'issuer') as ConfigurationTypeInput;
      expect(issuerData.value).toBe('issuer');
      const privateKeyData = configurationData.find((config) => config.key === 'privateKey') as ConfigurationTypeInput;
      expect(privateKeyData.value).not.toBe('myPK'); // should be encrypted
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

    it('should edit whole configuration entity', async () => {
      const editFieldInConfig: EditInput = {
        key: 'configuration',
        value: [
          { key: 'callbackUrl', value: 'http://myopencti/auth/samlTestDomain/callback', type: 'string' },
          { key: 'idpCert', value: '21341234', type: 'string' },
          { key: 'issuer', value: 'issuer', type: 'string' },
          { key: 'newKey', value: 'newKey', type: 'string' },
        ],
      };

      const result = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_UPDATE,
        variables: {
          id: createdSingleSignOn1Id,
          input: [editFieldInConfig],
        },
      });

      expect(result?.data?.singleSignOnFieldPatch).toBeDefined();
      expect(result?.data?.singleSignOnFieldPatch?.name).toBe('updated name 1');
      const configurationData: ConfigurationTypeInput[] = result?.data?.singleSignOnFieldPatch?.configuration as ConfigurationTypeInput[];
      expect(configurationData).toEqual([
        { key: 'callbackUrl', value: 'http://myopencti/auth/samlTestDomain/callback', type: 'string' },
        { key: 'idpCert', value: '21341234', type: 'string' },
        { key: 'issuer', value: 'issuer', type: 'string' },
        { key: 'newKey', value: 'newKey', type: 'string' },
      ]);
    });

    it('should edit one single configuration entity', async () => {
      const editFieldInConfig: EditInput = {
        key: 'configuration',
        object_path: 'configuration',
        operation: EditOperation.Add,
        value: [{ key: 'issuer2', value: 'issuer2', type: 'string' }],
      };

      const result = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_UPDATE,
        variables: {
          id: createdSingleSignOn1Id,
          input: [editFieldInConfig],
        },
      });

      expect(result?.data?.singleSignOnFieldPatch).toBeDefined();
      expect(result?.data?.singleSignOnFieldPatch?.name).toBe('updated name 1');

      const configurationData: ConfigurationTypeInput[] = result?.data?.singleSignOnFieldPatch?.configuration as ConfigurationTypeInput[];
      expect(configurationData).toEqual([
        { key: 'callbackUrl', value: 'http://myopencti/auth/samlTestDomain/callback', type: 'string' },
        { key: 'idpCert', value: '21341234', type: 'string' },
        { key: 'issuer', value: 'issuer', type: 'string' },
        { key: 'newKey', value: 'newKey', type: 'string' },
        { key: 'issuer2', value: 'issuer2', type: 'string' },
      ]);
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

describe('SSO: Local strategy dedicated behaviour', () => {
  let localStrategyId: string;
  it('should get Local Strategy', async () => {
    const localStrategy = await queryAsAdminWithSuccess({
      query: SINGLE_SIGN_ON_LIST_QUERY,
      variables: {
        filters: {
          mode: FilterMode.And,
          filters: [{ key: ['strategy'], values: [StrategyType.LocalStrategy], operator: FilterOperator.Eq }],
          filterGroups: [],
        },
      },
    });
    expect(localStrategy).toBeDefined();
    console.log('YOP:', { data: JSON.stringify(localStrategy?.data) });
    expect(localStrategy?.data?.singleSignOns.edges[0].node.identifier).toBe('local');
    localStrategyId = localStrategy?.data?.singleSignOns.edges[0].node.id;
  });
  it('should not create 2nd Local Strategy', async () => {
    const createInput: SingleSignOnAddInput = {
      name: 'local2',
      strategy: StrategyType.LocalStrategy,
      enabled: true,
      identifier: 'local2',
      configuration: [
        { key: 'label', value: 'local label', type: 'string' },
      ],
    };
    await queryAsUserIsExpectedError(USER_SECURITY.client, {
      query: SINGLE_SIGN_ON_CREATE,
      variables: { input: createInput },
    }, 'Local Strategy already exists in database', 'FUNCTIONAL_ERROR');
  });
  it('should not delete Local Strategy', async () => {
    await queryAsUserIsExpectedError(USER_SECURITY.client, {
      query: SINGLE_SIGN_ON_DELETE,
      variables: { id: localStrategyId },
    }, 'Cannot delete Local Strategy', 'FUNCTIONAL_ERROR');
  });
  it('should delete Local Strategy', async () => {
    await deleteElementById(testContext, ADMIN_USER, localStrategyId, ENTITY_TYPE_SINGLE_SIGN_ON);
    const singleSignOnList = await queryAsAdminWithSuccess({
      query: SINGLE_SIGN_ON_LIST_QUERY,
      variables: { first: 10 },
    });

    expect(singleSignOnList).toBeDefined();
    const ssoList = singleSignOnList?.data?.singleSignOns.edges;
    expect(ssoList.find((item: any) => item?.node?.id === localStrategyId)).toBeUndefined();
    expect(ssoList.find((item: any) => item?.node?.id === localStrategyId)).toBeUndefined();
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
});
