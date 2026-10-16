import type { ModuleDescriptor } from '../module-descriptor';
import ingestionHealthTypeDefs from './ingestionHealth.graphql';
import ingestionHealthResolvers from './ingestionHealth-resolvers';
import { ingestionHealthSettingsAttribute } from './ingestionHealth-attributes';

const ingestionHealthModule: ModuleDescriptor = {
  id: 'ingestionHealth',
  // The ingestion health settings are stored in the platform settings, read and edited through ingestionHealth-domain
  settingsAttributes: [ingestionHealthSettingsAttribute],
  // The health fields are resolved on the entities that carry them (connectors, feeds and syncs), see ingestionHealthFieldResolvers
  graphqlSchemas: [{ schema: ingestionHealthTypeDefs, resolver: ingestionHealthResolvers }],
};

export default ingestionHealthModule;
