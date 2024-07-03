import csvMapper_deprecated from './csvMapper-resolver';
import csvMapperTypeDefs from './csvMapper.graphql';
import { registerGraphqlSchema } from '../../../../graphql/schema';

registerGraphqlSchema({
  schema: csvMapperTypeDefs,
  resolver: csvMapper_deprecated,
});
