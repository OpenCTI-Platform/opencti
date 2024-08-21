/**
 * Placeholder for Module Definition
 */

import type { OverviewLayoutCustomization } from '../entitySetting/entitySetting-types';
import { registerEntityOverviewLayoutCustomization } from '../../schema/overviewLayoutCustomization-register';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../schema/stixMetaObject';

const externalReferenceDefaultOverviewLayout: OverviewLayoutCustomization[] = [
  { key: 'basicInformation', width: 6, label: 'Basic information' },
  { key: 'details', width: 6, label: 'Entity details' },
  { key: 'linkedObjects', width: 6, label: 'Linked objects' },
  { key: 'uploadedFiles', width: 6, label: 'Uploaded files' },
];

// Register only the default layout
registerEntityOverviewLayoutCustomization(
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  externalReferenceDefaultOverviewLayout,
);
