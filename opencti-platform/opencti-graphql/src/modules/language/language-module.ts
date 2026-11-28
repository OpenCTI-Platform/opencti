import type { ModuleDescriptor } from '../module-descriptor';
import { LANGUAGE_DEFINITION } from './language';
import languageTypeDefs from './language.graphql';
import languageResolvers from './language-resolver';

const languageModule: ModuleDescriptor = {
  id: 'language',
  dataModel: [LANGUAGE_DEFINITION],
  graphqlSchemas: [{ schema: languageTypeDefs, resolver: languageResolvers }],
};

export default languageModule;
