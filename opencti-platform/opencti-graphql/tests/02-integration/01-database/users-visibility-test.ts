import { beforeAll, describe, expect } from 'vitest';
import gql from 'graphql-tag';
import { getOrganizationIdByName, queryAsAdmin } from '../../utils/testQuery';

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

const ORGANIZATION_ADD_QUERY = gql`
  mutation UserOrganizationAddMutation(
    $id: ID!
    $organizationId: ID!
  ) {
    userEdit(id: $id) {
      organizationAdd(organizationId: $organizationId) {
        id
      }
    }
  }
`;

describe('Users visibility according to their direct organizations', () => {
  beforeAll(async () => {
    // ------ Create the context with users and organizations -------
    // userA participate-to orgaA, userB participate-to orgaB
    // orgaA and orgaB part of orgaAB
    // userC part of orgaAB
    // userO part of no organization
    // with ParticipateToPartsRule inferrence rule activated: userA and userB participate-to orgaAB via inferred relationships
    
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

    const userAInternalId = users.find((u) => u.data?.userAdd.name === 'userA')?.data?.userAdd.id;
    const userBInternalId = users.find((u) => u.data?.userAdd.name === 'userB')?.data?.userAdd.id;
    const userABInternalId = users.find((u) => u.data?.userAdd.name === 'userAB')?.data?.userAdd.id;

    // ParticipateToPartsRule
  });
});