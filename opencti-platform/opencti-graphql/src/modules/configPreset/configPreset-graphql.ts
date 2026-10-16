import { CONFIG_PRESET_FEATURE_FLAG, isFeatureEnabled } from '../../config/conf';
import { registerGraphqlSchema } from '../../graphql/schema';
import configPresetTypeDefs from './configPreset.graphql';
import configPresetResolvers from './configPreset-resolver';

if (isFeatureEnabled(CONFIG_PRESET_FEATURE_FLAG)) {
  registerGraphqlSchema({
    schema: configPresetTypeDefs,
    resolver: configPresetResolvers,
  });
}
