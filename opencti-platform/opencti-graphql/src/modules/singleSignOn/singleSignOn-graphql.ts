import { registerGraphqlSchema } from '../../graphql/schema';
import singleSignOnTypeDefs from './singleSignOn.graphql';
import singleSignOnResolver from './singleSignOn-resolver';

registerGraphqlSchema({
  schema: singleSignOnTypeDefs,
  resolver: singleSignOnResolver,
});
