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
  { name: PULSE_SETTINGS_SECTOR, label: 'Threat Pulse sector bucket', type: 'string', format: 'enum', values: [...PULSE_SECTOR_BUCKETS], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: PULSE_SETTINGS_REGION, label: 'Threat Pulse region bucket', type: 'string', format: 'enum', values: [...PULSE_REGION_BUCKETS], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: PULSE_SETTINGS_CONSENT_VERSION, label: 'Threat Pulse consent version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: PULSE_SETTINGS_CONSENT_DATE, label: 'Threat Pulse consent date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: PULSE_SETTINGS_CONSENT_USER, label: 'Threat Pulse consent user', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
];
schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_SETTINGS, pulseSettingsAttributes);

const pulseEntityAttributes: Array<AttributeDefinition> = [
  { name: PULSE_ATTRIBUTE_KEYS, label: 'Threat Pulse keys', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
  { name: PULSE_ATTRIBUTE_PREVALENCE, label: 'Community prevalence', type: 'string', format: 'enum', values: PULSE_PREVALENCE_VALUES, mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: PULSE_ATTRIBUTE_TREND, label: 'Community trend', type: 'string', format: 'enum', values: PULSE_TREND_VALUES, mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: PULSE_ATTRIBUTE_SECTOR_TREND, label: 'Sector trend', type: 'string', format: 'enum', values: PULSE_TREND_VALUES, mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: PULSE_ATTRIBUTE_FIRST_SEEN, label: 'Network first seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: PULSE_ATTRIBUTE_UNIQUENESS, label: 'Community uniqueness', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  {
    name: PULSE_ATTRIBUTE_INFORMATION,
    label: 'Threat Pulse information',
    type: 'object',
    format: 'standard',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: false,
    mappings: [
      { name: 'published', label: 'Published on Threat Pulse', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      { name: 'platforms_bucket', label: 'Contributing platforms', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      { name: 'last_seen_network', label: 'Network last seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      { name: 'trend_series', label: 'Community trend series', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
      { name: 'sector_platforms_bucket', label: 'Sector contributing platforms', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      { name: 'updated_at', label: 'Threat Pulse update date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    ],
  },
];
PULSE_SCOPE_ENTITY_TYPES.forEach((entityType) => schemaAttributesDefinition.registerAttributes(entityType, pulseEntityAttributes));
