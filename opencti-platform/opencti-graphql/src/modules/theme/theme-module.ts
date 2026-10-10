import type { ModuleDescriptor } from '../module-descriptor';
import { THEME_DEFINITION } from './theme';
import themeResolvers from './theme-resolvers';
import themeTypeDefs from './theme.graphql';

const themeModule: ModuleDescriptor = {
  id: 'theme',
  dataModel: [THEME_DEFINITION],
  graphqlSchemas: [{ schema: themeTypeDefs, resolver: themeResolvers }],
};

export default themeModule;
