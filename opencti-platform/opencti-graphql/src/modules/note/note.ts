/**
 * Placeholder for Module Definition
 */

import type { OverviewLayoutCustomization } from '../entitySetting/entitySetting-types';
import { registerEntityOverviewLayoutCustomization } from '../../schema/overviewLayoutCustomization-register';
import { ENTITY_TYPE_CONTAINER_NOTE } from '../../schema/stixDomainObject';

const noteDefaultOverviewLayout: OverviewLayoutCustomization[] = [
  { key: 'details', width: 6, label: 'Entity details' },
  { key: 'basicInformation', width: 6, label: 'Basic information' },
  { key: 'relatedEntities', width: 12, label: 'Related entities' },
  { key: 'externalReferences', width: 6, label: 'External references' },
  { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
];

// Register only the default layout
registerEntityOverviewLayoutCustomization(
  ENTITY_TYPE_CONTAINER_NOTE,
  noteDefaultOverviewLayout,
);
