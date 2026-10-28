import type { ModuleDescriptor } from '../module-descriptor';
import { VOCABULARY_DEFINITION } from './vocabulary';
import vocabularyTypeDefs from './vocabulary.graphql';
import vocabularyResolvers from './vocabulary-resolver';

const vocabularyModule: ModuleDescriptor = {
  id: 'vocabulary',
  dataModel: [VOCABULARY_DEFINITION],
  graphqlSchemas: [{ schema: vocabularyTypeDefs, resolver: vocabularyResolvers }],
};

export default vocabularyModule;
