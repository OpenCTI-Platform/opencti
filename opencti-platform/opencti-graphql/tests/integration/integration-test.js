import { createTestClient } from 'apollo-server-testing';
import { ApolloServer } from 'apollo-server-express';
import schema from '../../src/schema/schema';

export const USER_ID = 'V1234';
const server = new ApolloServer({
  schema,
  context: () => ({
    user: {
      id: USER_ID,
      name: 'admin',
      email: 'admin@opencti.io',
      grant: ['ROLE_ADMIN', 'ROLE_ROOT']
    }
  })
});
export const { query } = createTestClient(server);

jest.setTimeout(15000);

require('./database/grakn');
require('./resolvers/user');
require('./resolvers/threatActor');
