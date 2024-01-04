import { registerGraphqlSchema } from '../../graphql/schema';
import notificationTypeDefs from './notifier.graphql';
import webhookResolvers from './notifier-resolver';

registerGraphqlSchema({
  schema: notificationTypeDefs,
  resolver: webhookResolvers,
});
