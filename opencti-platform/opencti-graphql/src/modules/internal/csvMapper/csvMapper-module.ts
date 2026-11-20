import type { ModuleDescriptor } from '../../module-descriptor';
import { CSV_MAPPER_DEFINITION } from './csvMapper';
import csvMapperTypeDefs from './csvMapper.graphql';
import csvMapperResolvers from './csvMapper-resolvers';
import csvMapper_deprecated from './deprecated/csvMapper-resolver';
import csvMapperTypeDefs_deprecated from './deprecated/csvMapper.graphql';

const csvMapperModule: ModuleDescriptor = {
  id: 'csvMapper',
  dataModel: [CSV_MAPPER_DEFINITION],
  graphqlSchemas: [
    { schema: csvMapperTypeDefs, resolver: csvMapperResolvers },
    { schema: csvMapperTypeDefs_deprecated, resolver: csvMapper_deprecated },
  ],
};

export default csvMapperModule;
