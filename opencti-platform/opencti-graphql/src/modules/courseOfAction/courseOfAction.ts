/**
 * Placeholder for Module Definition
 */

import type { OverviewLayoutCustomization } from '../entitySetting/entitySetting-types';
import { registerEntityOverviewLayoutCustomization } from '../../schema/overviewLayoutCustomization-register';
import { ENTITY_TYPE_COURSE_OF_ACTION } from '../../schema/stixDomainObject';

const courseOfActionDefaultOverviewLayout: OverviewLayoutCustomization[] = [
  { key: 'details', width: 6, label: 'Entity details' },
  { key: 'basicInformation', width: 6, label: 'Basic information' },
  { key: 'latestCreatedRelationships', width: 6, label: 'Latest created relationships' },
  { key: 'latestContainers', width: 6, label: 'Latest containers' },
  { key: 'externalReferences', width: 6, label: 'External references' },
  { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
  { key: 'notes', width: 12, label: 'Notes about this entity' },
];

// Register only the default layout
registerEntityOverviewLayoutCustomization(
  ENTITY_TYPE_COURSE_OF_ACTION,
  courseOfActionDefaultOverviewLayout,
);
