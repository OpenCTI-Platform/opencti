import { registerGraphqlSchema } from '../../graphql/schema';
import configPresetTypeDefs from './configPreset.graphql';
import configPresetResolvers from './configPreset-resolver';

registerGraphqlSchema({
  schema: configPresetTypeDefs,
  resolver: configPresetResolvers,
});
