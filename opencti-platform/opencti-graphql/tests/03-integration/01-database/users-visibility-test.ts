import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, editorQuery, getOrganizationIdByName, PLATFORM_ORGANIZATION, queryAsAdmin, securityQuery, testContext } from '../../utils/testQuery';
import { getInferences } from '../../utils/rule-utils';
import ParticipateToPartsRule from '../../../src/rules/participate-to-parts/ParticipateToPartsRule';
import { RELATION_PARTICIPATE_TO } from '../../../src/schema/internalRelationship';
import { adminQueryWithSuccess, enableCEAndUnSetOrganization, enableEEAndSetOrganization } from '../../utils/testQueryHelper';
import type { BasicConnection, BasicStoreBase, BasicStoreEntity, BasicStoreRelation } from '../../../src/types/store';
import { createRuleContent } from '../../../src/rules/rules-utils';
import { createInferredRelation, deleteInferredRuleElement } from '../../../src/database/middleware';
import { ID_SUBFILTER, RELATION_INFERRED_SUBFILTER, RELATION_TYPE_SUBFILTER } from '../../../src/utils/filtering/filtering-constants';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { findAllMembers, findMembersPaginated, resolveUserById } from '../../../src/domain/user';
import { getSettings, settingsEditField } from '../../../src/domain/settings';
import { getEntityFromCache, resetCacheForEntity } from '../../../src/database/cache';
import type { BasicStoreSettings } from '../../../src/types/settings';
import { SYSTEM_USER } from '../../../src/utils/access';
import { RELATION_OBJECT_ASSIGNEE } from '../../../src/schema/stixRefRelationship';
import type { AuthUser } from '../../../src/types/user';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';

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

const READ_MEMBERS_QUERY = gql`
  query members($entityTypes: [MemberType!], $filters: FilterGroup) {
    members(entityTypes: $entityTypes, filters: $filters) {
      edges {
        node {
          id
          entity_type
          name
        }
      }
    }
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
  let reportInternalId: string;
  const reportStandardId = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';

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

    // 03. Create the 2 inferred participate-to relationships
    // check there is no participate-to relationships before the creation
    let inferredParticipateToRelationships = await getInferences(RELATION_PARTICIPATE_TO) as BasicStoreRelation[];
    expect(inferredParticipateToRelationships.length).toBe(0);

    // create the inferred relationships
    const inputA = { fromId: userAInternalId, toId: organizationABId, relationship_type: RELATION_PARTICIPATE_TO };
    const inputB = { fromId: userBInternalId, toId: organizationABId, relationship_type: RELATION_PARTICIPATE_TO };
    const ruleContent = createRuleContent(ParticipateToPartsRule.id, [], [], {});
    await Promise.all(([inputA, inputB].map((input) => createInferredRelation(testContext, input, ruleContent))));

    // check the inferred relationships have been created
    inferredParticipateToRelationships = await getInferences(RELATION_PARTICIPATE_TO) as BasicStoreRelation[];
    expect(inferredParticipateToRelationships.length).toBe(2);

    // 04. Assign the 4 users to a report
    const REPORT_UPDATE_QUERY = gql`
      mutation ReportEdit($id: ID!, $input: [EditInput]!) {
        reportEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
            objectAssignee {
              id
              name
            }
          }
        }
      }
    `;
    const value = [userAInternalId, userBInternalId, userABInternalId, userOInternalId];
    const queryResult = await queryAsAdmin({
      query: REPORT_UPDATE_QUERY,
      variables: { id: reportStandardId, input: { key: 'objectAssignee', value } },
    });
    reportInternalId = queryResult.data?.reportEdit.fieldPatch.id;
    expect(queryResult.data?.reportEdit.fieldPatch.objectAssignee.length).toEqual(4);
  });

  afterAll(async () => {
    // Remove the inferred relationships
    const inferredRelationships = await getInferences(RELATION_PARTICIPATE_TO) as BasicStoreRelation[];
    await Promise.all(inferredRelationships.map((rel) => deleteInferredRuleElement(ParticipateToPartsRule.id, rel, [])));
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
  });

  describe('should regardingOf filter works with is_inferred subfilter', async () => {
    const generateRegardingOfFilters = (
      regardingOfOperator: 'eq' | 'not_eq',
      relationshipType?: string,
      isInferredSubFilterValue?: 'true' | 'false',
      organizationIds?: string[],
    ) => {
      const values = [];
      if (relationshipType) {
        values.push({
          key: RELATION_TYPE_SUBFILTER,
          values: [relationshipType],
        });
      }
      if (isInferredSubFilterValue) {
        values.push({
          key: RELATION_INFERRED_SUBFILTER,
          values: [isInferredSubFilterValue],
        });
      };
      if (organizationIds) {
        values.push({
          key: ID_SUBFILTER,
          values: organizationIds,
        });
      };
      return {
        mode: 'and',
        filters: [
          {
            key: 'name',
            values: ['userA', 'userB', 'userAB', 'userO'], // we only consider the users created in this file
          },
          {
            key: 'regardingOf',
            operator: regardingOfOperator,
            values,
          },
        ],
        filterGroups: [],
      };
    };

    it('regardingOf filter with not_eq operator and inferred subfilter should throw an error', async () => {
      const queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('not_eq', RELATION_PARTICIPATE_TO, 'false') } });
      expect(queryResult.errors?.[0].message).toEqual('regardingOf filter with inferred subfilter only supports eq operator');
    });

    it('regardingOf filter with no inferred subfilter and participate-to relationship type should fetch users participating in an organization', async () => {
      // 'eq' regardingOf with no inferred subfilter
      const eqQueryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO) } });
      expect(eqQueryResult.data?.users.edges.length).toEqual(3); // all the users participating in an organization
      expect(eqQueryResult.data?.users.edges.map((e: any) => e.node.name).includes('userA')).toBeTruthy();
      expect(eqQueryResult.data?.users.edges.map((e: any) => e.node.name).includes('userO')).toBeFalsy();

      // 'not_eq' regardingOf with no inferred subfilter
      const noteqQueryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('not_eq', RELATION_PARTICIPATE_TO) } });
      expect(noteqQueryResult.data?.users.edges.length).toEqual(1); // userO is in no organization
      expect(noteqQueryResult.data?.users.edges[0].node.name).toEqual('userO');
    });

    it('regardingOf filter with inferred subfilter set to false should fetch entities directly related to provided ids with provided relationship type', async () => {
      let queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'false') } });
      expect(queryResult.data?.users.edges.length).toEqual(3); // the users participating directly in an organization

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'false', [orgaAInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(1); // the users participating directly in organizationA
      expect(queryResult.data?.users.edges[0].node.name).toEqual('userA');

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'false', [orgaAInternalId, orgaABInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(2); // the users participating directly in organizationA or organizationAB
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userA')).toBeTruthy();
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userAB')).toBeTruthy();
    });

    it('regardingOf filter with inferred subfilter set to true should fetch entities having an inferred rel to provided ids with provided relationship type', async () => {
      let queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'true') } });
      expect(queryResult.data?.users.edges.length).toEqual(2); // the users involved in an inferred participate-to relationship
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userA')).toBeTruthy();
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userB')).toBeTruthy();

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'true', [orgaAInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(0); // the users involved in an inferred participate-to relationship with orgaA

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'true', [orgaABInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(2); // the users involved in an inferred participate-to relationship with orgaAB
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userA')).toBeTruthy();
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userB')).toBeTruthy();

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'true', [orgaABInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(2); // the users involved in an inferred participate-to relationship with orgaAB
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userA')).toBeTruthy();
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userB')).toBeTruthy();
    });

    it('regardingOf filter with inferred subfilter set to (false)/true and with NO RELATIONSHIP TYPE should fetch entities (not) having an inferred rel with the provided ids', async () => {
      let queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', undefined, 'true') } });
      expect(queryResult.errors?.[0].message).toEqual('Id or dynamic or relationship type are needed for this filtering key');

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', undefined, 'true', [orgaAInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(0); // no users have an inferred relationship with orgaA

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', undefined, 'true', [orgaAInternalId, orgaABInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(2); // users having an inferred relationship with orgaA or orgaAB
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userA')).toBeTruthy();
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userB')).toBeTruthy();

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', undefined, 'false', [orgaAInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(1); // users having a direct relationship with orgaA
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userA')).toBeTruthy();

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', undefined, 'false', [orgaAInternalId, orgaABInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(2); // users having a direct relationship with orgaA or orgaAB
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userA')).toBeTruthy();
      expect(queryResult.data?.users.edges.map((n: any) => n.node.name).includes('userAB')).toBeTruthy();
    });
  });

  describe('should fetch all the users if organization sharing is not activated', async () => {
    let USER_A: AuthUser;
    let USER_AB: AuthUser;

    beforeAll(async () => {
      // load the users
      USER_A = await resolveUserById(testContext, userAInternalId);
      USER_AB = await resolveUserById(testContext, userABInternalId);

      // check there is no platform organization
      const settings = await getEntityFromCache<BasicStoreSettings>(testContext, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
      expect(settings.platform_organization).toEqual(undefined);
    });

    it('should load members fetch all the users if no organization sharing', async () => {
      const filters = {
        mode: 'and',
        filters: [{
          key: 'name',
          values: ['userA', 'userB', 'userAB', 'userO'], // we only consider the users created in this file
        }],
        filterGroups: [],
      };
      const queryResult = await queryAsAdmin({ query: READ_MEMBERS_QUERY, variables: { filters } });
      expect(queryResult.data?.members.edges.filter((n: any) => n.node.entity_type === ENTITY_TYPE_USER).length).toEqual(4); // the admin can see all the users

      const paginatedMembersResult = await findMembersPaginated(testContext, USER_A, { filters }) as BasicConnection<BasicStoreEntity>;
      expect(paginatedMembersResult.edges.filter((n: any) => n.node.entity_type === ENTITY_TYPE_USER).length).toEqual(4); // the users visible by userA: userA and userO

      const membersResult = await findAllMembers(testContext, USER_AB, { filters }) as BasicStoreEntity[];
      expect(membersResult.length).toEqual(4); // the users visible by userA: userA and userO
    });

    it('should fetch all the assignees if no organization sharing', async () => {
      const report = await storeLoadById(testContext, ADMIN_USER, reportInternalId, ENTITY_TYPE_CONTAINER_REPORT);
      expect(report[RELATION_OBJECT_ASSIGNEE]?.length).toEqual(4);
    });
  });

  describe('should fetch members according to the user visibility if organization sharing is activated', async () => {
    let USER_A: AuthUser;
    let USER_AB: AuthUser;
    let USER_O: AuthUser;

    beforeAll(async () => {
      // load the users
      USER_A = await resolveUserById(testContext, userAInternalId);
      USER_AB = await resolveUserById(testContext, userABInternalId);
      USER_O = await resolveUserById(testContext, userOInternalId);

      // activate organization sharing
      await enableEEAndSetOrganization(PLATFORM_ORGANIZATION);
    });

    afterAll(async () => {
      // desactivate organization sharing
      await enableCEAndUnSetOrganization();
    });

    it('should load members according to the user visibility if orga sharing is activated', async () => {
      const filters = {
        mode: 'and',
        filters: [{
          key: 'name',
          values: ['userA', 'userB', 'userAB', 'userO'], // we only consider the users created in this file
        }],
        filterGroups: [],
      };
      // 01. with no entityTypes props
      let queryResult = await queryAsAdmin({ query: READ_MEMBERS_QUERY, variables: { filters } });
      expect(queryResult.data?.members.edges.filter((n: any) => n.node.entity_type === ENTITY_TYPE_USER).length).toEqual(4); // the admin can see all the users

      let paginatedMembersResult = await findMembersPaginated(testContext, USER_A, { filters }) as BasicConnection<BasicStoreEntity>;
      expect(paginatedMembersResult.edges.filter((n: any) => n.node.entity_type === ENTITY_TYPE_USER).length).toEqual(2); // the users visible by userA: userA and userO

      let membersResult = await findAllMembers(testContext, USER_AB, { filters }) as BasicStoreEntity[];
      expect(membersResult.length).toEqual(2); // the users visible by userAB: userAB and userO

      // 02. with entityTypes props
      // query
      queryResult = await queryAsAdmin({ query: READ_MEMBERS_QUERY, variables: { filters, entityTypes: [ENTITY_TYPE_USER] } });
      expect(queryResult.data?.members.edges.length).toEqual(4); // the admin can see all the users

      queryResult = await editorQuery({ query: READ_MEMBERS_QUERY, variables: { filters, entityTypes: [ENTITY_TYPE_USER] } });
      expect(queryResult.data?.members.edges.length).toEqual(1); // userO which is in no organization
      expect(queryResult.data?.members.edges[0].node.id).toEqual(userOInternalId);

      queryResult = await securityQuery({ query: READ_MEMBERS_QUERY, variables: { filters, entityTypes: [ENTITY_TYPE_USER] } });
      expect(queryResult.data?.members.edges.length).toEqual(4); // user with set_access rights can see all the users

      // fetch members with pagination
      paginatedMembersResult = await findMembersPaginated(testContext, USER_A, { filters, entityTypes: [ENTITY_TYPE_USER] }) as BasicConnection<BasicStoreEntity>;
      expect(paginatedMembersResult.edges.length).toEqual(2); // the users visible by userA: userA and userO
      expect(paginatedMembersResult.edges.map((n) => n.node.id).includes(userAInternalId)).toBeTruthy();
      expect(paginatedMembersResult.edges.map((n) => n.node.id).includes(userOInternalId)).toBeTruthy();

      paginatedMembersResult = await findMembersPaginated(testContext, USER_AB, { filters, entityTypes: [ENTITY_TYPE_USER] }) as BasicConnection<BasicStoreEntity>;
      expect(paginatedMembersResult.edges.length).toEqual(2); // the users visible by userA: userAB and userO

      paginatedMembersResult = await findMembersPaginated(testContext, USER_O, { filters, entityTypes: [ENTITY_TYPE_USER] }) as BasicConnection<BasicStoreEntity>;
      expect(paginatedMembersResult.edges.length).toEqual(1); // the users visible by userO: userO
      expect(paginatedMembersResult.edges[0].node.id).toEqual(userOInternalId);

      // fetch members with no pagination
      membersResult = await findAllMembers(testContext, USER_A, { filters }) as BasicStoreEntity[];
      expect(membersResult.length).toEqual(2);

      membersResult = await findAllMembers(testContext, USER_AB, { filters }) as BasicStoreEntity[];
      expect(membersResult.length).toEqual(2);

      membersResult = await findAllMembers(testContext, USER_O, { filters }) as BasicStoreEntity[];
      expect(membersResult.length).toEqual(1);
    });

    it('should load members load all the members if settings option view_all_users = true', async () => {
      // set option view_all_users to true
      const platformSettings: any = await getSettings(testContext);
      const inputTrue = [{ key: 'view_all_users', value: ['true'] }];
      let settingsResult = await settingsEditField(testContext, ADMIN_USER, platformSettings.id, inputTrue);
      expect(settingsResult.view_all_users).toBe(true);
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);

      const filters = {
        mode: 'and',
        filters: [{
          key: 'name',
          values: ['userA', 'userB', 'userAB', 'userO'], // we only consider the users created in this file
        }],
        filterGroups: [],
      };
      const queryResult = await editorQuery({ query: READ_MEMBERS_QUERY, variables: { filters, entityTypes: [ENTITY_TYPE_USER] } });
      expect(queryResult.data?.members.edges.length).toEqual(4);

      const membersResult = await findMembersPaginated(testContext, USER_O, { filters, entityTypes: [ENTITY_TYPE_USER] }) as BasicConnection<BasicStoreEntity>;
      expect(membersResult.edges.length).toEqual(4);

      // set option view_all_users to false
      const inputFalse = [{ key: 'view_all_users', value: ['false'] }];
      settingsResult = await settingsEditField(testContext, ADMIN_USER, platformSettings.id, inputFalse);
      expect(settingsResult.view_all_users).toBe(false);
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    });
  });
});
