import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../../schema/module';
import { createdAt, updatedAt } from '../../../schema/attribute-definition';
import { buildStixObject } from '../../../database/stix-2-1-converter';
import { cleanObject } from '../../../database/stix-converter-utils';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { ENTITY_TYPE_HUNT } from '../hunt-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_HUNT_HIT_RECORD, type StixHuntHitRecord, type StoreEntityHuntHitRecord } from './huntHitRecord-types';

const convertHuntHitRecordToStix = (instance: StoreEntityHuntHitRecord): StixHuntHitRecord => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.hit_key,
    hunt_id: instance.hunt_id,
    security_platform_id: instance.security_platform_id,
    hit_key: instance.hit_key,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({ ...stixObject.extensions[STIX_EXT_OCTI], extension_type: 'new-sdo' }),
    },
  };
};

const HUNT_HIT_RECORD_DEFINITION: ModuleDefinition<StoreEntityHuntHitRecord, StixHuntHitRecord> = {
  type: {
    id: 'hunt-hit-record',
    name: ENTITY_TYPE_HUNT_HIT_RECORD,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      // One record per hunt, security platform and hit
      [ENTITY_TYPE_HUNT_HIT_RECORD]: [{ src: 'hunt_id' }, { src: 'security_platform_id' }, { src: 'hit_key' }],
    },
    resolvers: {},
  },
  attributes: [
    createdAt,
    updatedAt,
    { name: 'hunt_id', label: 'Run hunt', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_HUNT], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'security_platform_id', label: 'Run security platform', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hit_key', label: 'Hit key', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'times_seen', label: 'Runs that found the hit', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'first_run_id', label: 'First run of the hit', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_run_id', label: 'Last run of the hit', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'counted_run_ids', label: 'Latest runs that found the hit', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'ioc_keys', label: 'Hit values', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixHuntHitRecord) => stix.hit_key,
  converter_2_1: convertHuntHitRecordToStix,
};

registerDefinition(HUNT_HIT_RECORD_DEFINITION);
