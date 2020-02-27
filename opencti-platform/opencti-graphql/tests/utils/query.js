import { ApolloServer } from 'apollo-server-express';
import { createTestClient } from 'apollo-server-testing';
import { BYPASS, ROLE_ADMINISTRATOR } from '../../src/domain/user';
import createSchema from '../../src/graphql/schema';

export const ONE_MINUTE = 60 * 1000;
export const TEN_MINUTE = 10 * ONE_MINUTE;
const ADMIN_USER = {
  id: 'V1234',
  name: 'admin',
  email: 'admin@opencti.io',
  roles: [{ name: ROLE_ADMINISTRATOR }],
  capabilities: [{ name: BYPASS }]
};

export const serverFromUser = (user = ADMIN_USER) => {
  return new ApolloServer({
    schema: createSchema(),
    context: () => ({ user })
  });
};

export const queryAsAdmin = createTestClient(serverFromUser()).query;
export const queryAsUser = user => createTestClient(serverFromUser(user)).query;
