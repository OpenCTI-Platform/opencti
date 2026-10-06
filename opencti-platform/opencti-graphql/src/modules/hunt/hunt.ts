import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { objectOrganization } from '../../schema/stixRefRelationship';
import convertHuntToStix from './hunt-converter';
import { HUNT_SOURCE_TYPES, HUNT_TARGET_TYPES, HUNT_TECHNIQUE_TYPES } from './hunt-entity-types';
import {
  ATTRIBUTE_HUNT_SOURCES,
  ATTRIBUTE_HUNT_TARGETS,
  ATTRIBUTE_HUNT_TECHNIQUES,
  ENTITY_TYPE_HUNT,
  HUNT_SOURCE_KINDS,
  HUNT_STATUSES,
  HUNT_TYPES,
  INPUT_HUNT_SOURCES,
  INPUT_HUNT_TARGETS,
  INPUT_HUNT_TECHNIQUES,
  RELATION_HUNT_SOURCES,
  RELATION_HUNT_TARGETS,
  RELATION_HUNT_TECHNIQUES,
  type StixHunt,
  type StoreEntityHunt,
} from './hunt-types';
import { huntStixBundle } from './hunt-pack';
import { validateHuntCreation, validateHuntUpdate } from './hunt-validators';

const HUNT_DEFINITION: ModuleDefinition<StoreEntityHunt, StixHunt> = {
  type: {
    id: 'hunt',
    name: ENTITY_TYPE_HUNT,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_HUNT]: [{ src: NAME_FIELD }],
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  overviewLayoutCustomization: [
    { key: 'details', width: 6, label: 'Entity details' },
    { key: 'basicInformation', width: 6, label: 'Basic information' },
    { key: 'huntStatistics', width: 12, label: 'Hunt statistics' },
    { key: 'latestRuns', width: 6, label: 'Latest runs' },
    { key: 'externalReferences', width: 6, label: 'External references' },
    { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
    { key: 'notes', width: 12, label: 'Notes about this entity' },
  ],
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'hypothesis', label: 'Hunt hypothesis', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    { name: 'hunt_type', label: 'Hunt type', type: 'string', format: 'enum', values: HUNT_TYPES, defaultValue: 'telemetry', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'hunt_status', label: 'Hunt status', type: 'string', format: 'enum', values: HUNT_STATUSES, defaultValue: 'active', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'hunt_source_kind', label: 'Hunt origin', type: 'string', format: 'enum', values: HUNT_SOURCE_KINDS, defaultValue: 'analyst', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'sigma_rule', label: 'Hunt Sigma rule', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'native_queries', label: 'Hunt native queries', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, upsert_force_replace: true, isFilterable: false },
    { name: 'hunt_ioc_filters', label: 'Hunt indicator filters', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'hunt_ioc_values', label: 'Hunt pasted values', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, upsert_force_replace: true, isFilterable: false },
    { name: 'hunt_scope', label: 'Hunt scope', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'hunt_schedule', label: 'Hunt schedule', type: 'string', format: 'short', defaultValue: 'manual', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'trigger_filters', label: 'Hunt trigger filters', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'hunt_pir_activation', label: 'Activate with PIR', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'time_window_hours', label: 'Hunt time window (hours)', type: 'numeric', precision: 'integer', defaultValue: 24, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'expected_observables', label: 'Hunt expected observables', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, upsert_force_replace: true, isFilterable: false },
    { name: 'benign_patterns', label: 'Hunt benign patterns', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, upsert_force_replace: true, isFilterable: false },
    { name: 'escalation_threshold', label: 'Hunt escalation threshold', type: 'numeric', precision: 'integer', defaultValue: 10, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'escalate_manual_runs', label: 'Escalate manual runs', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'hunt_max_results', label: 'Hunt maximum results per run', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    // Run statistics, written by the platform without stream events
    { name: 'last_run_at', label: 'Hunt last run date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_run_status', label: 'Hunt last run status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_hits_count', label: 'Hunt last run hits', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_new_hits_count', label: 'Hunt last run new hits', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'next_run_at', label: 'Hunt next run date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hunt_pir_armed', label: 'Hunt armed by a PIR', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hunt_pir_armed_at', label: 'Hunt PIR arming date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  relationsRefs: [
    {
      name: INPUT_HUNT_TARGETS,
      type: 'ref',
      databaseName: RELATION_HUNT_TARGETS,
      stixName: ATTRIBUTE_HUNT_TARGETS,
      label: 'Hunt targets',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: true,
      isRefExistingForTypes(this, fromType, toType) {
        return fromType === ENTITY_TYPE_HUNT && this.toTypes.includes(toType);
      },
      isFilterable: true,
      toTypes: HUNT_TARGET_TYPES,
    },
    {
      name: INPUT_HUNT_TECHNIQUES,
      type: 'ref',
      databaseName: RELATION_HUNT_TECHNIQUES,
      stixName: ATTRIBUTE_HUNT_TECHNIQUES,
      label: 'Hunt techniques',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: true,
      isRefExistingForTypes(this, fromType, toType) {
        return fromType === ENTITY_TYPE_HUNT && this.toTypes.includes(toType);
      },
      isFilterable: true,
      toTypes: HUNT_TECHNIQUE_TYPES,
    },
    {
      name: INPUT_HUNT_SOURCES,
      type: 'ref',
      databaseName: RELATION_HUNT_SOURCES,
      stixName: ATTRIBUTE_HUNT_SOURCES,
      label: 'Hunt sources',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: true,
      isRefExistingForTypes(this, fromType, toType) {
        return fromType === ENTITY_TYPE_HUNT && this.toTypes.includes(toType);
      },
      isFilterable: true,
      toTypes: HUNT_SOURCE_TYPES,
    },
    objectOrganization,
  ],
  validators: {
    validatorCreation: validateHuntCreation,
    validatorUpdate: validateHuntUpdate,
  },
  representative: (stix: StixHunt) => {
    return stix.name;
  },
  converter_2_1: convertHuntToStix,
  bundleResolver: huntStixBundle,
};

registerDefinition(HUNT_DEFINITION);
