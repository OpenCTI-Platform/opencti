import { APIRequestContext } from '@playwright/test';
import { getRoles } from './role.data';

export const getGroups = () => `
  query {
    groups {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

interface AddGroupInput {
  name: string;
  roles: string[];
}

const addGroup = (input: AddGroupInput) => `
  mutation {
    groupAdd(input: {
      name: "${input.name}",
      group_confidence_level: {
        max_confidence: 100,
        overrides: []
      },
    }) {
      id
      name
    }
  }
`;

const addGroupRole = (groupId: string, roleId: string) => `
  mutation {
    groupEdit(id: "${groupId}") {
      relationAdd(input: {
        toId: "${roleId}",
        relationship_type: "has-role",
      }) {
        id
      }
    }
  }
`;

export const addGroups = async (request: APIRequestContext, groups: AddGroupInput[]) => {
  const rolesResponse = await request.post('/graphql', { data: { query: getRoles() } });
  const rolesResponseData = JSON.parse((await rolesResponse.body()).toString());
  const roles = rolesResponseData.data.roles.edges.map((e: any) => e.node);

  const existingGroupsResponse = await request.post('/graphql', { data: { query: getGroups() } });
  const existingGroupsResponseData = JSON.parse((await existingGroupsResponse.body()).toString());
  const existingGroups = existingGroupsResponseData.data.groups.edges.map((e: any) => e.node.name);

  await Promise.all(groups.map(async (group) => {
    if (!existingGroups.includes(group.name)) {
      const addGroupResponse = await request.post('/graphql', { data: { query: addGroup(group) } });

      if (group.roles && group.roles.length > 0) {
        const groupRoles = roles.filter((role: any) => group.roles?.includes(role.name));
        const addGroupResponseData = JSON.parse((await addGroupResponse.body()).toString());
        const groupId = addGroupResponseData.data.groupAdd.id;

        await Promise.all(groupRoles.map(async (role: any) => {
          await request.post('/graphql', { data: { query: addGroupRole(groupId, role.id) } });
        }));
      }
    }
  }));
};
