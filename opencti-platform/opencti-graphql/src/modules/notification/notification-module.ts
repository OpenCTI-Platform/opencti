import type { ModuleDescriptor } from '../module-descriptor';
import { TRIGGER_DEFINITION, NOTIFICATION_DEFINITION } from './notification';
import notificationTypeDefs from './notification.graphql';
import notificationResolvers from './notification-resolver';

const notificationModule: ModuleDescriptor = {
  id: 'notification',
  dataModel: [TRIGGER_DEFINITION, NOTIFICATION_DEFINITION],
  graphqlSchemas: [{ schema: notificationTypeDefs, resolver: notificationResolvers }],
};

export default notificationModule;
