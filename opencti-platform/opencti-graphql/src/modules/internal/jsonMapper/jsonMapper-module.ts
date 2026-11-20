import type { ModuleDescriptor } from '../../module-descriptor';
import { JSON_MAPPER_DEFINITION } from './jsonMapper';
import jsonMapperTypeDefs from './jsonMapper.graphql';
import jsonMapperResolvers from './jsonMapper-resolvers';

const jsonMapperModule: ModuleDescriptor = {
  id: 'jsonMapper',
  dataModel: [JSON_MAPPER_DEFINITION],
  graphqlSchemas: [{ schema: jsonMapperTypeDefs, resolver: jsonMapperResolvers }],
};

export default jsonMapperModule;
