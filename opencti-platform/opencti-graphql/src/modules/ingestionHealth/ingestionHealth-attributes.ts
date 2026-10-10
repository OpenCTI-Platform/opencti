import { INGESTION_HEALTH_FEATURE_FLAG } from '../../config/conf';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { INGESTION_HEALTH_STATUSES } from './ingestionHealth-types';

// Health cache, written by the ingestion health manager on change only (RFC 0001 §4.4).
// This is what the UI reads: the manager is the only evaluator.
// Registered on connectors and on the feeds (CSV, JSON, RSS, TAXII, TAXII collection) and the syncs; only connectors are evaluated for now.
// Not registered at all when the INGESTION_HEALTH feature flag is off.
export const ingestionHealthAttributes: AttributeDefinition[] = [
  {
    name: 'ingestion_health_status',
    label: 'Ingestion health status',
    type: 'string',
    format: 'enum',
    values: [...INGESTION_HEALTH_STATUSES],
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
    featureFlag: INGESTION_HEALTH_FEATURE_FLAG,
  },
  {
    name: 'ingestion_health_since',
    label: 'Ingestion health since',
    type: 'date',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
    featureFlag: INGESTION_HEALTH_FEATURE_FLAG,
  },
  {
    name: 'ingestion_health_summary',
    label: 'Ingestion health summary',
    type: 'string',
    format: 'text',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: false,
    featureFlag: INGESTION_HEALTH_FEATURE_FLAG,
  },
  {
    // JSON array of IngestionCheck, like connector_state
    name: 'ingestion_health_checks',
    label: 'Ingestion health checks',
    type: 'string',
    format: 'json',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: false,
    featureFlag: INGESTION_HEALTH_FEATURE_FLAG,
  },
];
