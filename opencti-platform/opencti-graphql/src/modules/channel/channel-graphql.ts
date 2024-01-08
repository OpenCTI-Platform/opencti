import { registerGraphqlSchema } from '../../graphql/schema';
import channelTypeDefs from './channel.graphql';
import channelResolvers from './channel-resolver';

registerGraphqlSchema({
  schema: channelTypeDefs,
  resolver: channelResolvers,
});
