import type { ModuleDescriptor } from '../module-descriptor';
import { NOTIFIER_DEFINITION } from './notifier';
import notificationTypeDefs from './notifier.graphql';
import webhookResolvers from './notifier-resolver';

const notifierModule: ModuleDescriptor = {
  id: 'notifier',
  dataModel: [NOTIFIER_DEFINITION],
  graphqlSchemas: [{ schema: notificationTypeDefs, resolver: webhookResolvers }],
};

export default notifierModule;
