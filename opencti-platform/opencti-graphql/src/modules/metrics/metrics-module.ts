import type { ModuleDescriptor } from '../module-descriptor';
import metricsResolver from './metrics-resolver';
import metricsTypeDefs from './metrics.graphql';

const metricsModule: ModuleDescriptor = {
  id: 'metrics',
  graphqlSchemas: [{ schema: metricsTypeDefs, resolver: metricsResolver }],
};

export default metricsModule;
