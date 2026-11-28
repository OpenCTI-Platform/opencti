import type { ModuleDescriptor } from '../module-descriptor';
import aiTypeDefs from './ai.graphql';
import aiResolvers from './ai-resolver';

const aiModule: ModuleDescriptor = {
  id: 'ai',
  graphqlSchemas: [{ schema: aiTypeDefs, resolver: aiResolvers }],
};

export default aiModule;
