import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import {
  type ConfigurationTypeInput,
  FilterMode,
  FilterOperator,
  type SingleSignMigrationInput,
  type SingleSignOnAddInput,
  type SingleSignOnEditInput,
  type SingleSignOnMigrationResult,
  StrategyType,
} from '../../../../src/generated/graphql';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedError, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER, testContext, USER_PARTICIPATE, USER_SECURITY } from '../../../utils/testQuery';
import { deleteElementById } from '../../../../src/database/middleware';
import { ENTITY_TYPE_SINGLE_SIGN_ON } from '../../../../src/modules/__singleSignOn/singleSignOn-types';
import { SECRET_TYPE } from '../../../../src/modules/__singleSignOn/singleSignOn-domain';

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
    mutation singleSignOnEdit($id: ID!, $input: SingleSignOnEditInput!) {
        singleSignOnEdit(id: $id, input: $input) {
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

describe('Single Sign On CRUD coverage', () => {
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
        { key: 'privateKey', value: 'myPK', type: SECRET_TYPE },
        { key: 'mySecret', value: 'Ilove;Mint', type: SECRET_TYPE },
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
          input: { name: 'updated name 1' } satisfies SingleSignOnEditInput,
        },
      });
    });
    it('should edit single sign on entity', async () => {
      const result = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_UPDATE,
        variables: {
          id: createdSingleSignOn1Id,
          input: { name: 'updated name 1' } satisfies SingleSignOnEditInput,
        },
      });

      expect(result?.data?.singleSignOnEdit).toBeDefined();
      expect(result?.data?.singleSignOnEdit?.name).toBe('updated name 1');
    });

    it('should edit whole configuration entity', async () => {
      const editInput: SingleSignOnEditInput = {
        configuration: [
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
          input: editInput,
        },
      });

      expect(result?.data?.singleSignOnEdit).toBeDefined();
      expect(result?.data?.singleSignOnEdit?.name).toBe('updated name 1');
      const configurationData: ConfigurationTypeInput[] = result?.data?.singleSignOnEdit?.configuration as ConfigurationTypeInput[];
      expect(configurationData).toEqual([
        { key: 'callbackUrl', value: 'http://myopencti/auth/samlTestDomain/callback', type: 'string' },
        { key: 'idpCert', value: '21341234', type: 'string' },
        { key: 'issuer', value: 'issuer', type: 'string' },
        { key: 'newKey', value: 'newKey', type: 'string' },
      ]);
    });

    it('should edit one single configuration entity', async () => {
      const editInput: SingleSignOnEditInput = {
        configuration: [{ key: 'issuer2', value: 'issuer2', type: 'string' }],
      };

      const result = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_UPDATE,
        variables: {
          id: createdSingleSignOn1Id,
          input: editInput,
        },
      });

      expect(result?.data?.singleSignOnEdit).toBeDefined();
      expect(result?.data?.singleSignOnEdit?.name).toBe('updated name 1');

      const configurationData: ConfigurationTypeInput[] = result?.data?.singleSignOnEdit?.configuration as ConfigurationTypeInput[];
      expect(configurationData).toEqual([
        { key: 'issuer2', value: 'issuer2', type: 'string' },
      ]);
    });

    it('should edit single sign on entity with group management', async () => {
      const result = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_UPDATE,
        variables: {
          id: createdSingleSignOn1Id,
          input: {
            groups_management: {
              groups_path: ['member'],
              groups_mapping: [
                '/Connector:Connectors',
              ],
            } } satisfies SingleSignOnEditInput,
        },
      });
      expect(result?.data?.singleSignOnEdit).toBeDefined();
      expect(result?.data?.singleSignOnEdit?.groups_management.groups_path).toStrictEqual(['member']);
      expect(result?.data?.singleSignOnEdit?.groups_management.groups_mapping).toStrictEqual(['/Connector:Connectors']);
    });

    it('should not edit empty value in input', async () => {
      const editInput: SingleSignOnEditInput = {
        configuration: [
          { key: 'callbackUrl', value: 'http://myopencti/auth/samlTestDomain/callback', type: 'string' },
          { key: 'idpCert', value: '21341234', type: 'string' },
          { key: 'issuer', value: 'issuer', type: 'string' },
          { key: 'newKey', value: 'newKey', type: 'string' },
          { key: 'issuer2', value: 'issuer2', type: 'string' },
          { key: 'privateKey', value: '', type: 'string' },
        ],
      };

      const result = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_UPDATE,
        variables: {
          id: createdSingleSignOn1Id,
          input: editInput,
        },
      });
      expect(result?.data?.singleSignOnEdit).toBeDefined();
      const configurationData: ConfigurationTypeInput[] = result?.data?.singleSignOnEdit?.configuration as ConfigurationTypeInput[];
      expect(configurationData).not.toContainEqual({ key: 'privateKey' });
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
});
