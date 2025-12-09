import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import {
  ADMIN_USER,
  createHttpClient,
  editorQuery,
  getOrganizationIdByName,
  GREEN_GROUP,
  PLATFORM_ORGANIZATION,
  queryAsAdmin,
  securityQuery,
  testContext,
  userQuery,
} from '../../utils/testQuery';
import { getInferences } from '../../utils/rule-utils';
import ParticipateToPartsRule from '../../../src/rules/participate-to-parts/ParticipateToPartsRule';
import { RELATION_PARTICIPATE_TO } from '../../../src/schema/internalRelationship';
import { adminQueryWithSuccess, unSetOrganization, setOrganization } from '../../utils/testQueryHelper';
import type { BasicStoreBase, BasicStoreRelation } from '../../../src/types/store';
import { createRuleContent } from '../../../src/rules/rules-utils';
import { createInferredRelation, deleteInferredRuleElement } from '../../../src/database/middleware';
import { ID_SUBFILTER, RELATION_INFERRED_SUBFILTER, RELATION_TYPE_SUBFILTER } from '../../../src/utils/filtering/filtering-constants';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { findAllMembers, findMembersPaginated, resolveUserById } from '../../../src/domain/user';
import { getSettings, settingsEditField } from '../../../src/domain/settings';
import { getEntityFromCache, resetCacheForEntity } from '../../../src/database/cache';
import type { BasicStoreSettings } from '../../../src/types/settings';
import { SYSTEM_USER } from '../../../src/utils/access';
import type { AuthUser } from '../../../src/types/user';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { addReport } from '../../../src/domain/report';
import type { AxiosInstance } from 'axios';
import { INPUT_ASSIGNEE, INPUT_PARTICIPANT } from '../../../src/schema/general';
import { MARKING_TLP_GREEN } from '../../../src/schema/identifier';

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

const READ_ASSIGNEES_QUERY = gql`
  query assignees($entityTypes: [String!]) {
    assignees(entityTypes: $entityTypes) {
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

const READ_PARTICIPANTS_QUERY = gql`
  query participants($entityTypes: [String!]) {
    participants(entityTypes: $entityTypes) {
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

const READ_REPORT_QUERY = gql`
  query report($id: String) {
    report(id: $id) {
      id
      name
      objectAssignee {
        id
        name
      }
      objectParticipant {
        id
        name
      }
    }
  }
`;

const visibleAssigneesFromQueryResult = (queryResult: any) => {
  return queryResult.data?.report?.[INPUT_ASSIGNEE]?.filter((n: { id: string; name: string }) => n.name !== 'Restricted');
};

const visibleParticipantsFromQueryResult = (queryResult: any) => {
  return queryResult.data?.report?.[INPUT_PARTICIPANT]?.filter((n: { id: string; name: string }) => n.name !== 'Restricted');
};

describe('Users visibility according to their direct organizations', () => {
  let userAInternalId: string;
  let userA2InternalId: string;
  let userBInternalId: string;
  let userABInternalId: string;
  let userOInternalId: string;
  let userServiceAccountInternalId: string;

  let orgaAInternalId: string;
  let orgaBInternalId: string;
  let orgaABInternalId: string;
  let orgaCInternalId: string;

  let USER_A: AuthUser;
  let USER_A2: AuthUser;
  let USER_AB: AuthUser;
  let USER_O: AuthUser;

  let USER_A_CLIENT: AxiosInstance;
  let USER_A2_CLIENT: AxiosInstance;
  let USER_AB_CLIENT: AxiosInstance;

  let reportInternalId: string;

  const usersNames = ['userA', 'userA2', 'userB', 'userAB', 'userO', 'userServiceAccount'];

  // grouping of 'it' to test all the users are fetched in different contexts
  // the parameters are function to ensure the variables are initialized
  const shouldFetchAllTheUsers = async (
    fetchUserA: () => AuthUser,
    fetchUserAB: () => AuthUser,
    fetchUserO: () => AuthUser,
    fetchUserAClient: () => AxiosInstance,
    fetchUserA2Client: () => AxiosInstance,
    fetchReportInternalId: () => string,
    contextExplanation: string,
  ) => {
    let USER_A: AuthUser;
    let USER_AB: AuthUser;
    let USER_O: AuthUser;
    let USER_A_CLIENT: AxiosInstance;
    let USER_A2_CLIENT: AxiosInstance;
    let reportInternalId: string;

    beforeAll(() => {
      USER_A = fetchUserA();
      USER_AB = fetchUserAB();
      USER_O = fetchUserO();
      USER_A_CLIENT = fetchUserAClient();
      USER_A2_CLIENT = fetchUserA2Client();
      reportInternalId = fetchReportInternalId();
    });

    it(`should load members fetch all the users if ${contextExplanation}`, async () => {
      const filters = {
        mode: 'and',
        filters: [{
          key: 'name',
          values: usersNames, // we only consider the users created in this file
        }],
        filterGroups: [],
      };
      let queryResult = await queryAsAdmin({ query: READ_MEMBERS_QUERY, variables: { filters } });
      expect(queryResult.data?.members.edges.filter((n: any) => n.node.entity_type === ENTITY_TYPE_USER).length).toEqual(6); // the admin can see all the users

      queryResult = await editorQuery({ query: READ_MEMBERS_QUERY, variables: { filters, entityTypes: [ENTITY_TYPE_USER] } });
      expect(queryResult.data?.members.edges.length).toEqual(6);

      let paginatedMembersResult = await findMembersPaginated(testContext, USER_A, { filters });
      expect(paginatedMembersResult.edges.filter((n: any) => n.node.entity_type === ENTITY_TYPE_USER).length).toEqual(6);

      paginatedMembersResult = await findMembersPaginated(testContext, USER_A2, { filters });
      expect(paginatedMembersResult.edges.filter((n: any) => n.node.entity_type === ENTITY_TYPE_USER).length).toEqual(6);

      paginatedMembersResult = await findMembersPaginated(testContext, USER_O, { filters, entityTypes: [ENTITY_TYPE_USER] });
      expect(paginatedMembersResult.edges.length).toEqual(6);

      let membersResult = await findAllMembers(testContext, USER_AB, { filters });
      expect(membersResult.length).toEqual(6);

      membersResult = await findAllMembers(testContext, USER_O, { filters });
      expect(membersResult.length).toEqual(6);
    });

    it(`should fetch all the assignees and participants of a report if ${contextExplanation}`, async () => {
      let reportQueryResult = await queryAsAdmin({ query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
      expect(visibleAssigneesFromQueryResult(reportQueryResult).length).toEqual(6); // all the assignees of the report
      expect(visibleParticipantsFromQueryResult(reportQueryResult).length).toEqual(6); // all the participants of the report

      reportQueryResult = await userQuery(USER_A_CLIENT, { query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
      expect(visibleAssigneesFromQueryResult(reportQueryResult).length).toEqual(6);
      expect(visibleParticipantsFromQueryResult(reportQueryResult).length).toEqual(6);

      reportQueryResult = await userQuery(USER_A2_CLIENT, { query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
      expect(visibleAssigneesFromQueryResult(reportQueryResult).length).toEqual(6);
      expect(visibleParticipantsFromQueryResult(reportQueryResult).length).toEqual(6);
    });

    it(`should fetch all the users that are assignees of a report if ${contextExplanation}`, async () => {
      let queryResult = await queryAsAdmin({ query: READ_ASSIGNEES_QUERY, variables: { entityTypes: [ENTITY_TYPE_CONTAINER_REPORT] } });
      expect(queryResult.data?.assignees.edges.length).toEqual(6);

      queryResult = await userQuery(USER_A_CLIENT, { query: READ_ASSIGNEES_QUERY, variables: { entityTypes: [ENTITY_TYPE_CONTAINER_REPORT] } });
      expect(queryResult.data?.assignees.edges.length).toEqual(6);

      queryResult = await userQuery(USER_A2_CLIENT, { query: READ_ASSIGNEES_QUERY, variables: { entityTypes: [ENTITY_TYPE_CONTAINER_REPORT] } });
      expect(queryResult.data?.assignees.edges.length).toEqual(6);
    });

    it(`should fetch all the users that are participants if ${contextExplanation}`, async () => {
      let queryResult = await queryAsAdmin({ query: READ_PARTICIPANTS_QUERY, variables: {} });
      expect(queryResult.data?.participants.edges.length).toEqual(6);

      queryResult = await editorQuery({ query: READ_PARTICIPANTS_QUERY, variables: {} });
      expect(queryResult.data?.participants.edges.length).toEqual(6);

      queryResult = await userQuery(USER_A_CLIENT, { query: READ_PARTICIPANTS_QUERY, variables: { entityTypes: [ENTITY_TYPE_CONTAINER_REPORT] } });
      expect(queryResult.data?.participants.edges.length).toEqual(6);

      queryResult = await userQuery(USER_A2_CLIENT, { query: READ_PARTICIPANTS_QUERY, variables: { entityTypes: [ENTITY_TYPE_CONTAINER_REPORT] } });
      expect(queryResult.data?.participants.edges.length).toEqual(6);
    });
  };

  beforeAll(async () => {
    // ------ Create the context with users and organizations -------
    // userA and userA2 participate-to orgaA, userA2 has not the right to see orgaA because of markings
    // userB participate-to orgaB
    // orgaA and orgaB part of orgaAB
    // userAB part of orgaAB
    // userO part of no organization
    // userServiceAccount part of orgaC and with user_service_account=true
    // with ParticipateToPartsRule inference rule activated: userA, userA2 and userB participate-to orgaAB via inferred relationships

    // 01. Create the organizations
    const ORGANIZATIONS_TO_CREATE = [
      { input: { name: 'orgaA', objectMarking: [MARKING_TLP_GREEN] } },
      { input: { name: 'orgaB' } },
      { input: { name: 'orgaAB' } },
      { input: { name: 'orgaC' } },
    ];
    const organizations = await Promise.all(ORGANIZATIONS_TO_CREATE.map((orgaToCreate) => queryAsAdmin({
      query: CREATE_ORGANIZATION_QUERY,
      variables: orgaToCreate,
    })));
    expect(organizations.length).toEqual(4);
    expect(organizations[0].data?.organizationAdd.name).toEqual('orgaA');

    orgaAInternalId = organizations.find((o) => o.data?.organizationAdd.name === 'orgaA')?.data?.organizationAdd.id;
    orgaBInternalId = organizations.find((o) => o.data?.organizationAdd.name === 'orgaB')?.data?.organizationAdd.id;
    orgaABInternalId = organizations.find((o) => o.data?.organizationAdd.name === 'orgaAB')?.data?.organizationAdd.id;
    orgaCInternalId = organizations.find((o) => o.data?.organizationAdd.name === 'orgaC')?.data?.organizationAdd.id;

    // 02. Create the users and link them with their organization
    // Users are part of a group with knowledge capabilities
    const organizationAId = await getOrganizationIdByName('orgaA');
    const organizationBId = await getOrganizationIdByName('orgaB');
    const organizationABId = await getOrganizationIdByName('orgaAB');
    const organizationCId = await getOrganizationIdByName('orgaC');

    const USER_TO_CREATE_A = {
      input: {
        name: 'userA',
        password: 'userA',
        user_email: 'userA@mail.com',
        objectOrganization: [organizationAId],
        groups: [GREEN_GROUP.id],
      },
    };
    USER_A_CLIENT = createHttpClient(USER_TO_CREATE_A.input.user_email, USER_TO_CREATE_A.input.password);
    const USER_TO_CREATE_A2 = {
      input: {
        name: 'userA2',
        password: 'userA2',
        user_email: 'userA2@mail.com',
        objectOrganization: [organizationAId],
      },
    };
    USER_A2_CLIENT = createHttpClient(USER_TO_CREATE_A2.input.user_email, USER_TO_CREATE_A2.input.password);
    const USER_TO_CREATE_B = {
      input: {
        name: 'userB',
        password: 'userB',
        user_email: 'userB@mail.com',
        objectOrganization: [organizationBId],
      },
    };
    const USER_TO_CREATE_AB = {
      input: {
        name: 'userAB',
        password: 'userAB',
        user_email: 'userAB@mail.com',
        objectOrganization: [organizationABId],
      },
    };
    USER_AB_CLIENT = createHttpClient(USER_TO_CREATE_AB.input.user_email, USER_TO_CREATE_AB.input.password);
    const USER_TO_CREATE_O = {
      input: {
        name: 'userO',
        password: 'userO',
        user_email: 'userO@mail.com',
      },
    };

    const USER_TO_CREATE_ServiceAccount = {
      input: {
        name: 'userServiceAccount',
        password: 'userServiceAccount',
        user_email: 'userServiceAccount@mail.com',
        objectOrganization: [organizationCId],
        user_service_account: true,
      },
    };

    const users = await Promise.all([USER_TO_CREATE_A, USER_TO_CREATE_A2, USER_TO_CREATE_B, USER_TO_CREATE_AB, USER_TO_CREATE_O, USER_TO_CREATE_ServiceAccount]
      .map((userToCreate) => queryAsAdmin({
        query: CREATE_USER_QUERY,
        variables: userToCreate,
      })));
    expect(users.length).toEqual(6);
    expect(users[0].data?.userAdd.name).toEqual('userA');
    expect(users[0].data?.userAdd.objectOrganization.edges.length).toEqual(1);
    expect(users[0].data?.userAdd.objectOrganization.edges[0].node.name).toEqual('orgaA');

    userAInternalId = users.find((u) => u.data?.userAdd.name === 'userA')?.data?.userAdd.id;
    userA2InternalId = users.find((u) => u.data?.userAdd.name === 'userA2')?.data?.userAdd.id;
    userBInternalId = users.find((u) => u.data?.userAdd.name === 'userB')?.data?.userAdd.id;
    userABInternalId = users.find((u) => u.data?.userAdd.name === 'userAB')?.data?.userAdd.id;
    userOInternalId = users.find((u) => u.data?.userAdd.name === 'userO')?.data?.userAdd.id;
    userServiceAccountInternalId = users.find((u) => u.data?.userAdd.name === 'userServiceAccount')?.data?.userAdd.id;

    // load the users
    USER_A = await resolveUserById(testContext, userAInternalId);
    USER_A2 = await resolveUserById(testContext, userA2InternalId);
    USER_AB = await resolveUserById(testContext, userABInternalId);
    USER_O = await resolveUserById(testContext, userOInternalId);

    // 03. Create the 2 inferred participate-to relationships
    // check there is no participate-to relationships before the creation
    let inferredParticipateToRelationships = await getInferences(RELATION_PARTICIPATE_TO) as BasicStoreRelation[];
    expect(inferredParticipateToRelationships.length).toBe(0);

    // create the inferred relationships
    const inputA = { fromId: userAInternalId, toId: organizationABId, relationship_type: RELATION_PARTICIPATE_TO };
    const inputA2 = { fromId: userA2InternalId, toId: organizationABId, relationship_type: RELATION_PARTICIPATE_TO };
    const inputB = { fromId: userBInternalId, toId: organizationABId, relationship_type: RELATION_PARTICIPATE_TO };
    const ruleContent = createRuleContent(ParticipateToPartsRule.id, [], [], {});
    await Promise.all(([inputA, inputA2, inputB].map((input) => createInferredRelation(testContext, input, ruleContent))));

    // check the inferred relationships have been created
    inferredParticipateToRelationships = await getInferences(RELATION_PARTICIPATE_TO) as BasicStoreRelation[];
    expect(inferredParticipateToRelationships.length).toBe(3);

    // 04. Create a report with all the users as assignees and participants
    const userIds = [userAInternalId, userA2InternalId, userBInternalId, userABInternalId, userOInternalId, userServiceAccountInternalId];
    const REPORT_TO_CREATE = {
      name: 'Report to test users visibility',
      published: new Date(),
      objectAssignee: userIds,
      objectParticipant: userIds,
    };

    // USER_A creates the report
    const report = await addReport(testContext, USER_A, REPORT_TO_CREATE);

    reportInternalId = report.id;
    expect(report.objectAssignee.length).toEqual(6);
    expect(report.objectParticipant.length).toEqual(6);
  });

  afterAll(async () => {
    // Delete the created report
    await stixDomainObjectDelete(testContext, SYSTEM_USER, reportInternalId, ENTITY_TYPE_CONTAINER_REPORT);
    // Remove the inferred relationships
    const inferredRelationships = await getInferences(RELATION_PARTICIPATE_TO) as BasicStoreRelation[];
    await Promise.all(inferredRelationships.map((rel) => deleteInferredRuleElement(ParticipateToPartsRule.id, rel, [])));
    // Check inferences have been deleted
    const afterDisableRelations = await getInferences(RELATION_PARTICIPATE_TO) as BasicStoreBase[];
    expect(afterDisableRelations.length).toBe(0);
    // Delete the users
    await Promise.all([userAInternalId, userA2InternalId, userBInternalId, userABInternalId, userOInternalId, userServiceAccountInternalId].map((userId) => queryAsAdmin({
      query: DELETE_USER_QUERY,
      variables: { id: userId },
    })));
    const userQueryResult = await adminQueryWithSuccess({ query: READ_USER_QUERY, variables: { id: userAInternalId } });
    expect(userQueryResult.data.user).toBeNull();
    // Delete the organizations
    await Promise.all([orgaAInternalId, orgaBInternalId, orgaABInternalId, orgaCInternalId].map((orgaId) => queryAsAdmin({
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
            values: usersNames, // we only consider the users created in this file
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

    it('regardingOf filter used with ids of entities the user has not access to should throw an error', async () => {
      const queryResult = await userQuery(USER_A2_CLIENT, { query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'false', [orgaAInternalId]) } });
      expect(queryResult.errors?.[0].message).toEqual('You are not allowed to do this.');
    });

    it('regardingOf filter with no inferred subfilter and participate-to relationship type should fetch users participating in an organization', async () => {
      // 'eq' regardingOf with no inferred subfilter
      const eqQueryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO) } });
      expect(eqQueryResult.data?.users.edges.length).toEqual(5); // all the users participating in an organization
      expect(eqQueryResult.data?.users.edges.map((e: any) => e.node.name).includes('userA')).toBeTruthy();
      expect(eqQueryResult.data?.users.edges.map((e: any) => e.node.name).includes('userO')).toBeFalsy();

      // 'not_eq' regardingOf with no inferred subfilter
      const noteqQueryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('not_eq', RELATION_PARTICIPATE_TO) } });
      expect(noteqQueryResult.data?.users.edges.length).toEqual(1); // userO is in no organization
      expect(noteqQueryResult.data?.users.edges[0].node.name).toEqual('userO');
    });

    it('regardingOf filter with inferred subfilter set to false should fetch entities directly related to provided ids with provided relationship type', async () => {
      let queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'false') } });
      expect(queryResult.data?.users.edges.length).toEqual(5); // the users participating directly in an organization

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'false', [orgaAInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(2); // the users participating directly in organizationA
      expect(['userA', 'userA2'].every((u) => queryResult.data?.users.edges.map((n: any) => n.node.name).includes(u))).toBeTruthy();

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'false', [orgaAInternalId, orgaABInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(3); // the users participating directly in organizationA or organizationAB
      expect(['userA', 'userA2', 'userAB'].every((u) => queryResult.data?.users.edges.map((n: any) => n.node.name).includes(u))).toBeTruthy();
    });

    it('regardingOf filter with inferred subfilter set to true should fetch entities having an inferred rel to provided ids with provided relationship type', async () => {
      let queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'true') } });
      expect(queryResult.data?.users.edges.length).toEqual(3); // the users involved in an inferred participate-to relationship
      expect(['userA', 'userA2', 'userB'].every((u) => queryResult.data?.users.edges.map((n: any) => n.node.name).includes(u))).toBeTruthy();

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'true', [orgaAInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(0); // the users involved in an inferred participate-to relationship with orgaA

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', RELATION_PARTICIPATE_TO, 'true', [orgaABInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(3); // the users involved in an inferred participate-to relationship with orgaAB
      expect(['userA', 'userA2', 'userB'].every((u) => queryResult.data?.users.edges.map((n: any) => n.node.name).includes(u))).toBeTruthy();
    });

    it('regardingOf filter with inferred subfilter set to (false)/true and with NO RELATIONSHIP TYPE should fetch entities (not) having an inferred rel with the provided ids', async () => {
      let queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', undefined, 'true') } });
      expect(queryResult.errors?.[0].message).toEqual('Id or dynamic or relationship type are needed for this filtering key');

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', undefined, 'true', [orgaAInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(0); // no users have an inferred relationship with orgaA

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', undefined, 'true', [orgaAInternalId, orgaABInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(3); // users having an inferred relationship with orgaA or orgaAB
      expect(['userA', 'userA2', 'userB'].every((u) => queryResult.data?.users.edges.map((n: any) => n.node.name).includes(u))).toBeTruthy();

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', undefined, 'false', [orgaAInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(2); // users having a direct relationship with orgaA
      expect(['userA', 'userA2'].every((u) => queryResult.data?.users.edges.map((n: any) => n.node.name).includes(u))).toBeTruthy();

      queryResult = await queryAsAdmin({ query: LIST_USERS_QUERY, variables: { filters: generateRegardingOfFilters('eq', undefined, 'false', [orgaAInternalId, orgaABInternalId]) } });
      expect(queryResult.data?.users.edges.length).toEqual(3); // users having a direct relationship with orgaA or orgaAB
      expect(['userA', 'userA2', 'userAB'].every((u) => queryResult.data?.users.edges.map((n: any) => n.node.name).includes(u))).toBeTruthy();
    });
  });

  describe('should fetch all the users if organization sharing is not activated', async () => {
    beforeAll(async () => {
      // check there is no platform organization
      const settings = await getEntityFromCache<BasicStoreSettings>(testContext, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
      expect(settings.platform_organization).toEqual(undefined);
    });

    await shouldFetchAllTheUsers(
      () => USER_A,
      () => USER_AB,
      () => USER_O,
      () => USER_A_CLIENT,
      () => USER_A2_CLIENT,
      () => reportInternalId,
      'no organization sharing',
    );
  });

  describe('should fetch users according to the user visibility if organization sharing is activated', async () => {
    beforeAll(async () => {
      // activate organization sharing
      await setOrganization(PLATFORM_ORGANIZATION);
    });

    afterAll(async () => {
      // deactivate organization sharing
      await unSetOrganization();
    });

    it('should load members according to the user visibility if organization sharing is activated', async () => {
      const filters = {
        mode: 'and',
        filters: [{
          key: 'name',
          values: usersNames, // we only consider the users created in this file
        }],
        filterGroups: [],
      };
      // 01. with no entityTypes props
      let queryResult = await queryAsAdmin({ query: READ_MEMBERS_QUERY, variables: { filters } });
      expect(queryResult.data?.members.edges.length).toEqual(6); // the admin can see all the users

      let paginatedMembersResult = await findMembersPaginated(testContext, USER_A, { filters });
      expect(paginatedMembersResult.edges.length).toEqual(4); // the users visible by userA: userA, userA2, userO, userServiceAccount

      paginatedMembersResult = await findMembersPaginated(testContext, USER_A2, { filters });
      expect(paginatedMembersResult.edges.length).toEqual(4); // the users visible by userA2: userA, userA2, userO, userServiceAccount

      let membersResult = await findAllMembers(testContext, USER_AB, { filters });
      expect(membersResult.length).toEqual(3); // the users visible by userAB: userAB, userO, userServiceAccount

      // 02. with entityTypes props
      // query
      queryResult = await queryAsAdmin({ query: READ_MEMBERS_QUERY, variables: { filters, entityTypes: [ENTITY_TYPE_USER] } });
      expect(queryResult.data?.members.edges.length).toEqual(6); // the admin can see all the users

      queryResult = await editorQuery({ query: READ_MEMBERS_QUERY, variables: { filters, entityTypes: [ENTITY_TYPE_USER] } });
      expect(queryResult.data?.members.edges.length).toEqual(2); // userO which is in no organization, and userServiceAccount
      expect([userOInternalId, userServiceAccountInternalId].every((u) => queryResult.data?.members.edges.map((n: any) => n.node.id).includes(u))).toBeTruthy();

      queryResult = await securityQuery({ query: READ_MEMBERS_QUERY, variables: { filters, entityTypes: [ENTITY_TYPE_USER] } });
      expect(queryResult.data?.members.edges.length).toEqual(6); // user with set_access rights can see all the users

      // fetch members with pagination
      paginatedMembersResult = await findMembersPaginated(testContext, USER_A, { filters, entityTypes: [ENTITY_TYPE_USER] });
      expect(paginatedMembersResult.edges.length).toEqual(4); // the users visible by userA: userA, userA2, userO, userServiceAccount
      expect([userAInternalId, userA2InternalId, userOInternalId, userServiceAccountInternalId]
        .every((u) => paginatedMembersResult.edges.map((n) => n.node.id).includes(u))).toBeTruthy();

      paginatedMembersResult = await findMembersPaginated(testContext, USER_A2, { filters, entityTypes: [ENTITY_TYPE_USER] });
      expect(paginatedMembersResult.edges.length).toEqual(4); // the users visible by userA2: userA, userA2, userO, userServiceAccount
      expect([userAInternalId, userA2InternalId, userOInternalId, userServiceAccountInternalId]
        .every((u) => paginatedMembersResult.edges.map((n) => n.node.id).includes(u))).toBeTruthy();

      paginatedMembersResult = await findMembersPaginated(testContext, USER_AB, { filters, entityTypes: [ENTITY_TYPE_USER] });
      expect(paginatedMembersResult.edges.length).toEqual(3); // the users visible by userAB: userAB, userO, userServiceAccount
      expect([userABInternalId, userOInternalId, userServiceAccountInternalId]
        .every((u) => paginatedMembersResult.edges.map((n) => n.node.id).includes(u))).toBeTruthy();

      paginatedMembersResult = await findMembersPaginated(testContext, USER_O, { filters, entityTypes: [ENTITY_TYPE_USER] });
      expect(paginatedMembersResult.edges.length).toEqual(2); // the users visible by userO: userO and userServiceAccount
      expect([userOInternalId, userServiceAccountInternalId]
        .every((u) => paginatedMembersResult.edges.map((n) => n.node.id).includes(u))).toBeTruthy();

      // fetch members with no pagination
      membersResult = await findAllMembers(testContext, USER_A, { filters });
      expect(membersResult.length).toEqual(4);

      membersResult = await findAllMembers(testContext, USER_A2, { filters });
      expect(membersResult.length).toEqual(4);

      membersResult = await findAllMembers(testContext, USER_AB, { filters });
      expect(membersResult.length).toEqual(3);

      membersResult = await findAllMembers(testContext, USER_O, { filters });
      expect(membersResult.length).toEqual(2);
    });

    it('should fetch the assignees and participants of a given report according to the user visibility if organization sharing is activated', async () => {
      let reportQueryResult = await queryAsAdmin({ query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
      expect(visibleAssigneesFromQueryResult(reportQueryResult).length).toEqual(6); // all the assignees of the report
      expect(visibleParticipantsFromQueryResult(reportQueryResult).length).toEqual(6); // all the participants of the report

      reportQueryResult = await userQuery(USER_A_CLIENT, { query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
      expect(reportQueryResult.data?.report?.[INPUT_ASSIGNEE]?.length).toEqual(6); // all the users before filtering the restricted ones
      expect(visibleAssigneesFromQueryResult(reportQueryResult).length).toEqual(4); // userA, userA2, userO, userServiceAccount
      expect(visibleParticipantsFromQueryResult(reportQueryResult).length).toEqual(4); // userA, userA2, userO, userServiceAccount

      reportQueryResult = await userQuery(USER_A2_CLIENT, { query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
      expect(visibleAssigneesFromQueryResult(reportQueryResult).length).toEqual(4); // userA, userA2, userO, userServiceAccount
      expect(visibleParticipantsFromQueryResult(reportQueryResult).length).toEqual(4); // userA, userA2, userO, userServiceAccount

      reportQueryResult = await userQuery(USER_AB_CLIENT, { query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
      expect(reportQueryResult.data?.report).toEqual(null); // the report is not visible for userAB
    });

    describe('should fetch all the users if organization sharing is activated and settings option view_all_users = true', async () => {
      beforeAll(async () => {
        // set option view_all_users to true
        const platformSettings = await getSettings(testContext);
        const inputTrue = [{ key: 'view_all_users', value: ['true'] }];
        const settingsResult = await settingsEditField(testContext, ADMIN_USER, platformSettings.id, inputTrue);
        expect(settingsResult.view_all_users).toBe(true);
        resetCacheForEntity(ENTITY_TYPE_SETTINGS);
      });

      afterAll(async () => {
        // set option view_all_users to false
        const inputFalse = [{ key: 'view_all_users', value: ['false'] }];
        const platformSettings = await getSettings(testContext);
        const settingsResult = await settingsEditField(testContext, ADMIN_USER, platformSettings.id, inputFalse);
        expect(settingsResult.view_all_users).toBe(false);
        resetCacheForEntity(ENTITY_TYPE_SETTINGS);
      });

      await shouldFetchAllTheUsers(
        () => USER_A,
        () => USER_AB,
        () => USER_O,
        () => USER_A_CLIENT,
        () => USER_A2_CLIENT,
        () => reportInternalId,
        'settings option view_all_users = true',
      );
    });
  });
});
