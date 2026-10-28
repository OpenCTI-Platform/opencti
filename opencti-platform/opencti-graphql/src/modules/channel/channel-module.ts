import type { ModuleDescriptor } from '../module-descriptor';
import { CHANNEL_DEFINITION } from './channel';
import channelTypeDefs from './channel.graphql';
import channelResolvers from './channel-resolver';

const channelModule: ModuleDescriptor = {
  id: 'channel',
  dataModel: [CHANNEL_DEFINITION],
  graphqlSchemas: [{ schema: channelTypeDefs, resolver: channelResolvers }],
};

export default channelModule;
