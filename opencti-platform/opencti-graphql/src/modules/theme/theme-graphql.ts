import { registerGraphqlSchema } from '../../graphql/schema';
import themeResolvers from './theme-resolvers';
import themeTypeDefs from './theme.graphql';

registerGraphqlSchema({
  schema: themeTypeDefs,
  resolver: themeResolvers,
});
