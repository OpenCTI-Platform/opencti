import { registerGraphqlSchema } from '../../../graphql/schema';
import jsonMapperTypeDefs from './jsonMapper.graphql';
import jsonMapperResolvers from './jsonMapper-resolvers';

registerGraphqlSchema({
  schema: jsonMapperTypeDefs,
  resolver: jsonMapperResolvers,
});
