import type { ModuleDescriptor } from '../module-descriptor';
import { ADMINISTRATIVE_AREA_DEFINITION } from './administrativeArea';
import administrativeAreaTypeDefs from './administrativeArea.graphql';
import administrativeAreaResolvers from './administrativeArea-resolver';

const administrativeAreaModule: ModuleDescriptor = {
  id: 'administrativeArea',
  dataModel: [ADMINISTRATIVE_AREA_DEFINITION],
  graphqlSchemas: [{ schema: administrativeAreaTypeDefs, resolver: administrativeAreaResolvers }],
};

export default administrativeAreaModule;
