import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { getOrganizationIdByName, ONE_MINUTE, queryAsAdmin, TEN_SECONDS } from '../../utils/testQuery';
import { activateRule, disableRule, getInferences } from '../../utils/rule-utils';
import ParticipateToPartsRule from '../../../src/rules/participate-to-parts/ParticipateToPartsRule';
import { wait } from '../../../src/database/utils';
import { RELATION_PARTICIPATE_TO } from '../../../src/schema/internalRelationship';
import { adminQueryWithSuccess } from '../../utils/testQueryHelper';
import type { BasicStoreBase } from '../../../src/types/store';

const CREATE_USER_QUERY = gql`
  mutation UserAdd($input: UserAddInput!) {
    userAdd(input: $input) {
      id
      standard_id
      name
      objectOrganization {
        edges {
          node {
            id
            name
          }
        }
      }
    }
  }
`;

const CREATE_ORGANIZATION_QUERY = gql`
  mutation OrganizationAdd($input: OrganizationAddInput!) {
    organizationAdd(input: $input) {
      id
      name
      description
      x_opencti_score
    }
  }
`;

const READ_USER_QUERY = gql`
  query user($id: String!) {
    user(id: $id) {
      id
      name
      objectOrganization {
        edges {
          node {
            id
            name
          }
        }
      }
    }
  }
`;

const LIST_USERS_QUERY = gql`
  query users($filters: FilterGroup) {
    users(filters: $filters) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const READ_ORGANIZATION_QUERY = gql`
  query organization($id: String!) {
    organization(id: $id) {
      id
      name
    }
  }
`;

const DELETE_USER_QUERY = gql`
  mutation userDelete($id: ID!) {
    userEdit(id: $id) {
      delete
    }
  }
`;

const DELETE_ORGANIZATION_QUERY = gql`
  mutation organizationDelete($id: ID!) {
    organizationDelete(id: $id)
  }
`;

describe('Users visibility according to their direct organizations', () => {
  let userAInternalId: string;
  let userBInternalId: string;
  let userABInternalId: string;
  let userOInternalId: string;
  let orgaAInternalId: string;
  let orgaBInternalId: string;
  let orgaABInternalId: string;

  beforeAll(async () => {
    // ------ Create the context with users and organizations -------
    // userA participate-to orgaA, userB participate-to orgaB
    // orgaA and orgaB part of orgaAB
    // userC part of orgaAB
    // userO part of no organization
    // with ParticipateToPartsRule inference rule activated: userA and userB participate-to orgaAB via inferred relationships
    
    // 01. Create the organizations
    const ORGANIZATIONS_TO_CREATE = [
      { input: { name: 'orgaA' } },
      { input: { name: 'orgaB' } },
      { input: { name: 'orgaAB' } },
    ];
    const organizations = await Promise.all(ORGANIZATIONS_TO_CREATE.map((orgaToCreate) => queryAsAdmin({
      query: CREATE_ORGANIZATION_QUERY,
      variables: orgaToCreate,
    })));
    expect(organizations.length).toEqual(3);
    expect(organizations[0].data?.organizationAdd.name).toEqual('orgaA');

    orgaAInternalId = organizations.find((o) => o.data?.organizationAdd.name === 'orgaA')?.data?.organizationAdd.id;
    orgaBInternalId = organizations.find((o) => o.data?.organizationAdd.name === 'orgaB')?.data?.organizationAdd.id;
    orgaABInternalId = organizations.find((o) => o.data?.organizationAdd.name === 'orgaAB')?.data?.organizationAdd.id;

    // 02. Create the users and link them with their orga
    const organizationAId = await getOrganizationIdByName('orgaA');
    const organizationBId = await getOrganizationIdByName('orgaB');
    const organizationABId = await getOrganizationIdByName('orgaAB');

    const USER_A = {
      input: {
        name: 'userA',
        password: 'userA',
        user_email: 'userA@mail.com',
        objectOrganization: [organizationAId],
      },
    };
    const USER_B = {
      input: {
        name: 'userB',
        password: 'userB',
        user_email: 'userB@mail.com',
        objectOrganization: [organizationBId],
      },
    };
    const USER_AB = {
      input: {
        name: 'userAB',
        password: 'userAB',
        user_email: 'userAB@mail.com',
        objectOrganization: [organizationABId],
      },
    };
    const USER_O = {
      input: {
        name: 'userO',
        password: 'userO',
        user_email: 'userO@mail.com',
      },
    };

    const users = await Promise.all([USER_A, USER_B, USER_AB, USER_O].map((userToCreate) => queryAsAdmin({
      query: CREATE_USER_QUERY,
      variables: userToCreate,
    })));
    expect(users.length).toEqual(4);
    expect(users[0].data?.userAdd.name).toEqual('userA');
    expect(users[0].data?.userAdd.objectOrganization.edges.length).toEqual(1);
    expect(users[0].data?.userAdd.objectOrganization.edges[0].node.name).toEqual('orgaA');

    userAInternalId = users.find((u) => u.data?.userAdd.name === 'userA')?.data?.userAdd.id;
    userBInternalId = users.find((u) => u.data?.userAdd.name === 'userB')?.data?.userAdd.id;
    userABInternalId = users.find((u) => u.data?.userAdd.name === 'userAB')?.data?.userAdd.id;
    userOInternalId = users.find((u) => u.data?.userAdd.name === 'userO')?.data?.userAdd.id;

    // activate ParticipateToPartsRule
    await activateRule(ParticipateToPartsRule.id);
    await wait(TEN_SECONDS); // let some time to rule manager to create the inferred relationships
    const afterEnableRelations = await getInferences(RELATION_PARTICIPATE_TO);
    expect(afterEnableRelations).toBe('test');
  }, ONE_MINUTE);

  describe('should regardingOf filter works with is_inferred subfilter', async () => {
    const generateFilters = (
      regardingOfOperator: 'eq' | 'not_eq',
      isInferredSubFilterValue?: boolean,
      organizationIds?: string[],
    ) => {
      const values = [{
          key: 'relationship_type',
          values: [RELATION_PARTICIPATE_TO]
        }];
      if (isInferredSubFilterValue) {
        values.push({
          key: 'is_inferred',
          values: [isInferredSubFilterValue ? 'true' : 'false']
        });
      };
      if (organizationIds) {
        values.push({
          key: 'id',
          values: organizationIds,
        });
      };
      return {
        mode: 'and',
        filters: [
          {
            key: 'name',
            values: ['userA', 'userB', 'userAB', 'userO'], // we only consider the user created in this file
          },
          {
            key: 'regardingOf',
            operator: regardingOfOperator,
            values,
          }
        ],
        filterGroups: [],
      };
    };

    it('regardingOf filter with no inferred subfilter and participate-to relationship type should fetch users participating in an organization', async () => {
      // 'eq' regardingOf with no inferred subfilter
      const eqQueryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateFilters('eq') } });
      expect(eqQueryResult.data?.users.edges.length).toEqual(3); // all the users participating in an organization
      expect(eqQueryResult.data?.users.edges.map((e: any) => e.node.name).includes('userA')).toBeTruthy();
      expect(eqQueryResult.data?.users.edges.map((e: any) => e.node.name).includes('userO')).toBeFalsy();

      // 'not_eq' regardingOf with no inferred subfilter
      const noteqQueryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateFilters('not_eq') } });
      expect(noteqQueryResult.data?.users.edges.length).toEqual(1); // userO is in no organization
      expect(noteqQueryResult.data?.users.edges[0].node.name).toEqual('userO');
    });

    it('regardingOf filter with inferred subfilter set to false should fetch entities directly related to provided ids with provided relationship type', async () => {
      let queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateFilters('eq', false) } });
      expect(queryResult.data?.users.edges.length).toEqual(3); // the users participating directly in an organization

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateFilters('eq', false, [orgaAInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(1); // the users participating directly in organizationA
      expect(queryResult.data?.users.edges[0].node.name).toEqual('userA');
    });
  });

  afterAll(async () => {
    // deactivate ParticipateToPartsRule rule
    await disableRule(ParticipateToPartsRule.id);
    // Check inferences have been deleted
    const afterDisableRelations = await getInferences(RELATION_PARTICIPATE_TO) as BasicStoreBase[];
    expect(afterDisableRelations.length).toBe(0);
    // Delete the users
    await Promise.all([userAInternalId, userBInternalId, userABInternalId, userOInternalId].map((userId) => queryAsAdmin({
      query: DELETE_USER_QUERY,
      variables: { id: userId },
    })));
    const userQueryResult = await adminQueryWithSuccess({ query: READ_USER_QUERY, variables: { id: userAInternalId } });
    expect(userQueryResult.data.user).toBeNull();
    // Delete the organizations
    await Promise.all([orgaAInternalId, orgaBInternalId, orgaABInternalId].map((orgaId) => queryAsAdmin({
      query: DELETE_ORGANIZATION_QUERY,
      variables: { id: orgaId },
    })));
    const orgaQueryResult = await adminQueryWithSuccess({ query: READ_ORGANIZATION_QUERY, variables: { id: orgaAInternalId } });
    expect(orgaQueryResult.data.organization).toBeNull();
  }, ONE_MINUTE);
});