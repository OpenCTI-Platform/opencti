import { registerGraphqlSchema } from '../../../graphql/schema';
import csvMapperTypeDefs from './csvMapper.graphql';
import csvMapperResolvers from './csvMapper-resolvers';

registerGraphqlSchema({
  schema: csvMapperTypeDefs,
  resolver: csvMapperResolvers,
});
