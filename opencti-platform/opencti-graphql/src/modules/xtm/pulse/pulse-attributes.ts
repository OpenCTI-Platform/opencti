import type { AttributeDefinition } from '../../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../../schema/internalObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../schema/stixMetaObject';
import {
  PULSE_ATTRIBUTE_FIRST_SEEN,
  PULSE_ATTRIBUTE_INFORMATION,
  PULSE_ATTRIBUTE_KEYS,
  PULSE_ATTRIBUTE_PREVALENCE,
  PULSE_ATTRIBUTE_SECTOR_TREND,
  PULSE_ATTRIBUTE_TREND,
  PULSE_ATTRIBUTE_UNIQUENESS,
  PULSE_ATTRIBUTE_PREVALENCE_RANK,
  PULSE_MODE_VALUES,
  PULSE_PREVALENCE_VALUES,
  PULSE_REGION_BUCKETS,
  PULSE_SCOPE_ENTITY_TYPES,
  PULSE_SECTOR_BUCKETS,
  PULSE_SETTINGS_CONSENT_DATE,
  PULSE_SETTINGS_CONSENT_USER,
  PULSE_SETTINGS_CONSENT_VERSION,
  PULSE_SETTINGS_EXCLUDED_MARKINGS,
  PULSE_SETTINGS_MODE,
  PULSE_SETTINGS_REGION,
  PULSE_SETTINGS_SCOPES,
  PULSE_SETTINGS_SECTOR,
  PULSE_TREND_VALUES,
} from './pulse-types';

const pulseSettingsAttributes: Array<AttributeDefinition> = [
  { name: PULSE_SETTINGS_MODE, label: 'Threat Pulse mode', type: 'string', format: 'enum', values: PULSE_MODE_VALUES, mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: PULSE_SETTINGS_SCOPES, label: 'Threat Pulse scopes', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
  { name: PULSE_SETTINGS_EXCLUDED_MARKINGS, label: 'Threat Pulse excluded markings', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_MARKING_DEFINITION], mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
  { name: PULSE_SETTINGS_SECTOR, label: 'Threat Pulse sector', type: 'string', format: 'enum', values: [...PULSE_SECTOR_BUCKETS], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: PULSE_SETTINGS_REGION, label: 'Threat Pulse region', type: 'string', format: 'enum', values: [...PULSE_REGION_BUCKETS], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: PULSE_SETTINGS_CONSENT_VERSION, label: 'Threat Pulse consent version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: PULSE_SETTINGS_CONSENT_DATE, label: 'Threat Pulse consent date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: PULSE_SETTINGS_CONSENT_USER, label: 'Threat Pulse consent user', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
];
schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_SETTINGS, pulseSettingsAttributes);

// Network data written by the read path only: never updated through the API, an import or an upsert.
const pulseEntityAttributes: Array<AttributeDefinition> = [
  { name: PULSE_ATTRIBUTE_KEYS, label: 'Threat Pulse keys', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, update: false, isFilterable: false },
  { name: PULSE_ATTRIBUTE_PREVALENCE, label: 'Community prevalence', type: 'string', format: 'enum', values: PULSE_PREVALENCE_VALUES, mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
  { name: PULSE_ATTRIBUTE_TREND, label: 'Community trend', type: 'string', format: 'enum', values: PULSE_TREND_VALUES, mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
  { name: PULSE_ATTRIBUTE_SECTOR_TREND, label: 'Sector trend', type: 'string', format: 'enum', values: PULSE_TREND_VALUES, mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
  { name: PULSE_ATTRIBUTE_FIRST_SEEN, label: 'Network first seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
  { name: PULSE_ATTRIBUTE_UNIQUENESS, label: 'Pulse community uniqueness', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
  // The sort key of the community prevalence, the same in preview and full mode.
  { name: PULSE_ATTRIBUTE_PREVALENCE_RANK, label: 'Community prevalence rank', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: false },
  // Read from the document source only, never searched: not indexed, so it costs one field of the index mapping.
  // Its shape is PulseStoredInformation (pulse-types.ts).
  { name: PULSE_ATTRIBUTE_INFORMATION, label: 'Threat Pulse information', type: 'object', format: 'raw', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: false },
];
PULSE_SCOPE_ENTITY_TYPES.forEach((entityType) => schemaAttributesDefinition.registerAttributes(entityType, pulseEntityAttributes));
