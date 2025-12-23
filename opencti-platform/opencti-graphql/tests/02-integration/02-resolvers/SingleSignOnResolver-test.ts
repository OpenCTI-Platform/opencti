import { describe, it, expect, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { StrategyType } from '../../../src/config/providers-configuration';
import type { StoreEntitySingleSignOn } from '../../../src/modules/singleSignOn/singleSignOn-types';
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
  let createdSingleSignOn_1: StoreEntitySingleSignOn;
  let createdSingleSignOn_2: StoreEntitySingleSignOn;

  describe('Create', async () => {
    const createInput: SingleSignOnAddInput = {
      name: 'test name 1',
      strategy: StrategyType.STRATEGY_SAML as unknown as StrategyTypeEnum,
      enabled: true,
    };
    const createInput2: SingleSignOnAddInput = {
      name: 'test name 2',
      strategy: StrategyType.STRATEGY_OPENID as unknown as StrategyTypeEnum,
      enabled: false,
    };

    beforeAll(async () => {
      const singleSignOn = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_CREATE,
        variables: { input: createInput },
      });
      const singleSignOn2 = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_CREATE,
        variables: { input: createInput2 },
      });
      createdSingleSignOn_1 = singleSignOn?.data?.singleSignOnAdd as StoreEntitySingleSignOn;
      createdSingleSignOn_2 = singleSignOn2?.data?.singleSignOnAdd as StoreEntitySingleSignOn;
    });

    it('should create single sign on entity', () => {
      expect(createdSingleSignOn_1.id).toBeDefined();
      expect(createdSingleSignOn_1.name).toBe('test name 1');
    });
    it('should create another single sign on entity', () => {
      expect(createdSingleSignOn_2.id).toBeDefined();
      expect(createdSingleSignOn_2.name).toBe('test name 2');
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
    });
  });
  describe('Update', () => {
    it('should edit the name of the single sign on entity', async () => {
      const result = await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_UPDATE,
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
        query: SINGLE_SIGN_ON_DELETE,
        variables: { id: createdSingleSignOn_1.id },
      });
      await queryAsAdminWithSuccess({
        query: SINGLE_SIGN_ON_DELETE,
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
    });
  });
});
