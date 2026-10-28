import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_SETTING_DEFINITION } from './entitySetting';
import entitySettingTypeDefs from './entitySetting.graphql';
import entitySettingResolvers from './entitySetting-resolvers';

const entitySettingModule: ModuleDescriptor = {
  id: 'entitySetting',
  dataModel: [ENTITY_SETTING_DEFINITION],
  graphqlSchemas: [{ schema: entitySettingTypeDefs, resolver: entitySettingResolvers }],
};

export default entitySettingModule;
