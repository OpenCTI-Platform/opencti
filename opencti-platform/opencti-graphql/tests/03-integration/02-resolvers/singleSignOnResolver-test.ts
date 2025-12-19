import { describe, it, expect } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { StrategyType } from '../../../src/config/providers-configuration';
import type { SingleSignOnAddInput, StrategyType as StrategyTypeEnum } from '../../../src/generated/graphql';

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
    it('should create single sign on entity', async () => {
      const createInput: SingleSignOnAddInput = {
        name: 'test name 1',
        strategy: StrategyType.STRATEGY_SAML as unknown as StrategyTypeEnum,
        enabled: true,
      };
      const singleSignOn = await queryAsAdminWithSuccess({
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
        strategy: StrategyType.STRATEGY_OPENID as unknown as StrategyTypeEnum,
        enabled: false,
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
    it('should list single sign on', async () => {
      const singleSignOnList = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_LIST_QUERY,
        variables: { first: 10 },
      });

      expect(singleSignOnList).toBeDefined();
      expect(singleSignOnList?.data?.singleSignOns.edges.length).toBe(2);
    });
  });
  describe('Update', () => {
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
  });
  describe('Delete', () => {
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
      expect(singleSignOnList?.data?.singleSignOns.edges.length).toBe(0);
    });
  });
});
