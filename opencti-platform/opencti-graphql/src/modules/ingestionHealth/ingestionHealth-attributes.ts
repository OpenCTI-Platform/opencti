import type { AttributeDefinition } from '../../schema/attribute-definition';
import { IngestionHealthStatus } from '../../generated/graphql';
import { INGESTION_HEALTH_FEATURE_FLAG } from '../../config/conf';

// Spread into the definition of every entity that carries an ingestion health: connectors, feeds and syncs
export const ingestionHealthAttributes: AttributeDefinition[] = [
  {
    name: 'ingestion_health',
    label: 'Ingestion health',
    type: 'object',
    format: 'nested',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: false,
    featureFlag: INGESTION_HEALTH_FEATURE_FLAG,
    mappings: [
      {
        name: 'status',
        label: 'Health status',
        type: 'string',
        format: 'enum',
        values: Object.values(IngestionHealthStatus),
        mandatoryType: 'internal',
        editDefault: false,
        multiple: false,
        upsert: false,
        isFilterable: false,
      },
      {
        name: 'status_since',
        label: 'Health status since',
        type: 'date',
        mandatoryType: 'internal',
        editDefault: false,
        multiple: false,
        upsert: false,
        isFilterable: false,
      },
      {
        name: 'last_event_date',
        label: 'Health last failure event date',
        type: 'date',
        mandatoryType: 'no',
        editDefault: false,
        multiple: false,
        upsert: false,
        isFilterable: false,
      },
      {
        name: 'health_checks',
        label: 'Health checks',
        type: 'object',
        format: 'nested',
        mandatoryType: 'no',
        editDefault: false,
        multiple: true,
        upsert: false,
        isFilterable: false,
        mappings: [
          { name: 'health_check_code', label: 'Health check code', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag: INGESTION_HEALTH_FEATURE_FLAG },
          { name: 'health_check_metadata', label: 'Health check metadata', type: 'object', format: 'raw', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag: INGESTION_HEALTH_FEATURE_FLAG },
        ],
      },
    ],
  },
];
