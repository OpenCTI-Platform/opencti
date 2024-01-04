import { registerGraphqlSchema } from '../../graphql/schema';
import entityPlaybookTypeDefs from './playbook.graphql';
import entityPlaybookResolvers from './playbook-resolvers';

registerGraphqlSchema({
  schema: entityPlaybookTypeDefs,
  resolver: entityPlaybookResolvers,
});
