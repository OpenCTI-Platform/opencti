import { APIRequestContext } from '@playwright/test';

const getUsers = () => `
  query {
    users {
      edges {
        node {
          name
        }
      }
    }
  }
`;

export interface AddUserInput {
  name: string
  user_email: string
  password: string
}

const addUser = (input: AddUserInput) => `
  mutation {
    userAdd(input: {
      name: "${input.name}",
      user_email: "${input.user_email}",
      password: "${input.password}",
    }) {
      id
      name
    }
  }
`;

export const addUsers = async (request: APIRequestContext, users: AddUserInput[]) => {
  const existingUsersResponse = await request.post('/graphql', { data: { query: getUsers() } });
  const existingUsersResponseData = JSON.parse((await existingUsersResponse.body()).toString());
  const existingUsers = existingUsersResponseData.data.users.edges.map((e: any) => e.node.name);

  await Promise.all(users.map(async (user) => {
    if (!existingUsers.includes(user.name)) {
      await request.post('/graphql', { data: { query: addUser(user) } });
    }
  }));
};
