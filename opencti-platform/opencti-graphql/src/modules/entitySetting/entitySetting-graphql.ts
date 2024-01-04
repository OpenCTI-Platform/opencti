import { registerGraphqlSchema } from '../../graphql/schema';
import entitySettingTypeDefs from './entitySetting.graphql';
import entitySettingResolvers from './entitySetting-resolvers';

registerGraphqlSchema({
  schema: entitySettingTypeDefs,
  resolver: entitySettingResolvers,
});
