import type { ModuleDescriptor } from '../module-descriptor';
import { EVENT_DEFINITION } from './event';
import eventTypeDefs from './event.graphql';
import eventResolvers from './event-resolver';

const eventModule: ModuleDescriptor = {
  id: 'event',
  dataModel: [EVENT_DEFINITION],
  graphqlSchemas: [{ schema: eventTypeDefs, resolver: eventResolvers }],
};

export default eventModule;
