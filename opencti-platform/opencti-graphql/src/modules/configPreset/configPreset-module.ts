import type { ModuleDescriptor } from '../module-descriptor';
import configPresetTypeDefs from './configPreset.graphql';
import configPresetResolvers from './configPreset-resolver';

const configPresetModule: ModuleDescriptor = {
  id: 'configPreset',
  graphqlSchemas: [{ schema: configPresetTypeDefs, resolver: configPresetResolvers }],
};

export default configPresetModule;
