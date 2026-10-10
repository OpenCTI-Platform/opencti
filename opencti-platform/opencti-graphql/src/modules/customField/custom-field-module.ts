import type { ModuleDescriptor } from '../module-descriptor';
import { CUSTOM_FIELD_DEFINITION_DEFINITION } from './custom-field';
import customFieldTypeDefs from './custom-field.graphql';
import customFieldResolvers from './custom-field-resolvers';

const customFieldModule: ModuleDescriptor = {
  id: 'customField',
  dataModel: [CUSTOM_FIELD_DEFINITION_DEFINITION],
  graphqlSchemas: [{ schema: customFieldTypeDefs, resolver: customFieldResolvers }],
};

export default customFieldModule;
