import { registerGraphqlSchema } from '../../graphql/schema';
import notificationTypeDefs from './notification.graphql';
import notificationResolvers from './notification-resolver';

registerGraphqlSchema({
  schema: notificationTypeDefs,
  resolver: notificationResolvers,
});
