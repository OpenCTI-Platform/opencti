import type { ModuleDescriptor } from '../module-descriptor';
import ingestionHealthTypeDefs from './ingestionHealth.graphql';

const ingestionHealthModule: ModuleDescriptor = {
  id: 'ingestionHealth',
  // Types only: the health fields are resolved on the entities that carry them (connectors)
  graphqlSchemas: [{ schema: ingestionHealthTypeDefs, resolver: {} }],
};

export default ingestionHealthModule;
