import registerRequireContextHook from 'babel-plugin-require-context-hook/register';
import { createTestClient } from 'apollo-server-testing';
import { ApolloServer } from 'apollo-server-express';
import createSchema from '../../src/graphql/schema';
import { initializeSchema } from '../../src/initialization';
import applyMigration from '../../src/database/migration';
import { ROLE_ADMINISTRATOR } from '../../src/domain/user';

// Initialize schema before tests
beforeAll(async () => {
  registerRequireContextHook();
  await initializeSchema();
  return applyMigration();
}, 120000);

// Setup the configuration
export const USER_ID = 'V1234';
const server = new ApolloServer({
  schema: createSchema(),
  context: () => ({
    user: {
      id: USER_ID,
      name: 'admin',
      email: 'admin@opencti.io',
      roles: [{ name: ROLE_ADMINISTRATOR }],
      capabilities: [{ name: 'BYPASS' }]
    }
  })
});
export const { query } = createTestClient(server);
jest.setTimeout(40000);

// Starting tests
require('./database/grakn');
require('./resolvers/user');
require('./resolvers/threatActor');
