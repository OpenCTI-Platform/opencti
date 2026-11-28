import type { ModuleDescriptor } from '../module-descriptor';
import ingestionHealthTypeDefs from './ingestionHealth.graphql';
import ingestionHealthResolvers from './ingestionHealth-resolvers';
import { ingestionHealthSettingsAttribute } from './ingestionHealth-attributes';
import { INGESTION_HEALTH_MANAGER_DEFINITION } from '../../manager/ingestionHealthManager';

const ingestionHealthModule: ModuleDescriptor = {
  id: 'ingestionHealth',
  // The ingestion health settings are stored in the platform settings, read and edited through ingestionHealth-domain
  settingsAttributes: [ingestionHealthSettingsAttribute],
  // The health fields are resolved on the entities that carry them (connectors, feeds and syncs), see ingestionHealthFieldResolvers
  graphqlSchemas: [{ schema: ingestionHealthTypeDefs, resolver: ingestionHealthResolvers }],
  managers: [INGESTION_HEALTH_MANAGER_DEFINITION],
};

export default ingestionHealthModule;
