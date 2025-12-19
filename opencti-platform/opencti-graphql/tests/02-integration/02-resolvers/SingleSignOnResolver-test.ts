import { describe, it, expect, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { StrategyType } from '../../../src/config//providers-configuration';
import type { StoreEntitySingleSignOn } from '../../../src/modules/singleSignOn/SingleSignOn-types';

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
export const SINGLE_SIGN_ON_LIST_CREATE = gql`
  mutation singleSignOnAdd($input: SingleSignOnAddInput!) {
    singleSignOnAdd(input: $input) {
      id
      name
      strategy
      enabled
    }
  }
`;
export const SINGLE_SIGN_ON_LIST_UPDATE = gql`
  mutation singleSignOnFieldPatch($id: ID!, $input: [EditInput!]!) {
    singleSignOnFieldPatch(id: $id, input: $input) {
      id
      name
      strategy
      enabled
    }
  }
`;
export const SINGLE_SIGN_ON_LIST_DELETE = gql`
  mutation singleSignOnDelete($id: ID!) {
    singleSignOnDelete(id: $id) 
  }
`;

describe('Single Sign On', () => {
  let createdSingleSignOn_1 = null;
  let createdSingleSignOn_2 = null;

  describe('Create', async () => {
    const createInput = {
      name: 'test name 1',
      strategy: StrategyType.STRATEGY_SAML,
      enabled: true,
    };
    const createInput2 = {
      name: 'test name 2',
      strategy: StrategyType.STRATEGY_OPENID,
      enabled: false,
    };

    beforeAll(async () => {
      const singleSignOn = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_LIST_CREATE,
        variables: { input: createInput },
      });
      const singleSignOn2 = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_LIST_CREATE,
        variables: { input: createInput2 },
      });
      createdSingleSignOn_1 = singleSignOn?.data?.singleSignOnAdd as StoreEntitySingleSignOn;
      createdSingleSignOn_2 = singleSignOn2?.data?.singleSignOnAdd as StoreEntitySingleSignOn;
    });

    it('should create single sign on entity', () => {
      expect(createdSingleSignOn_1.id).toBeDefined()
      expect(createdSingleSignOn_1.name).toBe("test name 1")
    });
    it('should create another single sign on entity', () => {
      expect(createdSingleSignOn_2.id).toBeDefined()
      expect(createdSingleSignOn_2.name).toBe("test name 2")
    });
  });
  describe('Find List', () => {
    it('should find a single sign on list', async () => {
      const singleSignOnList = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_LIST_QUERY,
        variables: { first: 10 },
      });

      expect(singleSignOnList).toBeDefined();
      expect(singleSignOnList?.data?.singleSignOns.edges.length).toBe(2);
    })
  });
  describe('Update', () => {
    it('should edit the name of the single sign on entity', async () => {
      const result = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_LIST_UPDATE,
        variables: {
          id: createdSingleSignOn_1.id,
          input: { key: 'name', value: 'updated name 1' },
        },
      });

      expect(result?.data?.singleSignOnFieldPatch).toBeDefined();
      expect(result?.data?.singleSignOnFieldPatch?.name).toBe('updated name 1');
    });
  });
  describe('Delete', () => {
    beforeAll(async () => {
      await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_LIST_DELETE,
        variables: { id: createdSingleSignOn_1.id },
      });
      await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_LIST_DELETE,
        variables: { id: createdSingleSignOn_2.id },
      });
    });

    it('should have deleted all single sign on entities', async () => {
      const singleSignOnList = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_LIST_QUERY,
        variables: { first: 10 },
      });

      expect(singleSignOnList).toBeDefined();
      expect(singleSignOnList?.data?.singleSignOns.edges.length).toBe(0);
    })
  });
});