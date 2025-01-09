import { registerGraphqlSchema } from '../../graphql/schema';
import templateTypeDefs from './fintelTemplate.graphql';
import fintelTemplateResolvers from './fintel-template-resolvers';

registerGraphqlSchema({
  schema: templateTypeDefs,
  resolver: fintelTemplateResolvers,
});
