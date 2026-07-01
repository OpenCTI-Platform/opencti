import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { normalizeName } from '../../schema/identifier';
import { createdAt, creators, updatedAt } from '../../schema/attribute-definition';
import {
  ATTRIBUTE_COVERED,
  ENTITY_TYPE_SECURITY_COVERAGE,
  INPUT_COVERED,
  RELATION_COVERED,
  type StixSecurityCoverage,
  type StoreEntitySecurityCoverage,
} from './securityCoverage-types';
import convertSecurityCoverageToStix from './securityCoverage-converter';
import { createdBy, objectLabel, objectMarking, objectOrganization } from '../../schema/stixRefRelationship';
import { COVERED_ENTITIES_TYPE, securityCoverageStixBundle } from './securityCoverage-domain';
import type { StoreEntity } from '../../types/store';
import { ATTRIBUTE_RESULT_OF, ENTITY_TYPE_SECURITY_COVERAGE_RESULT, INPUT_RESULT_OF, RELATION_RESULT_OF } from './securityCoverageResult/securityCoverageResult-types';

const SECURITY_COVERAGE_DEFINITION: ModuleDefinition<StoreEntitySecurityCoverage, StixSecurityCoverage> = {
  type: {
    id: 'security-coverage',
    name: ENTITY_TYPE_SECURITY_COVERAGE,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_SECURITY_COVERAGE]: [{ src: 'objectCovered' }],
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
      objectCovered(data: object) {
        return (data as StoreEntity).standard_id;
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'periodicity', /* PT1S */ label: 'Periodicity', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'duration', label: 'Duration', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'type_affinity', label: 'Type affinity', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'platforms_affinity', label: 'Platform(s) affinity', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    // TODO Move this field to upper level. Stix Domain Object
    { name: 'auto_enrichment_disable', label: 'Auto enrichment disable', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    creators,
    createdAt,
    updatedAt,
  ],
  relations: [],
  relationsRefs: [
    {
      name: INPUT_COVERED,
      type: 'ref',
      databaseName: RELATION_COVERED,
      stixName: ATTRIBUTE_COVERED,
      label: 'Coverage target',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: true,
      isRefExistingForTypes(this, fromType, toType) {
        return fromType === ENTITY_TYPE_SECURITY_COVERAGE && this.toTypes.includes(toType);
      },
      isFilterable: true,
      toTypes: COVERED_ENTITIES_TYPE,
    },
    {
      name: INPUT_RESULT_OF,
      type: 'ref',
      databaseName: RELATION_RESULT_OF,
      stixName: ATTRIBUTE_RESULT_OF,
      label: 'Security coverage results',
      mandatoryType: 'external',
      editDefault: false,
      multiple: true,
      upsert: true,
      isRefExistingForTypes(this, fromType, toType) {
        return fromType === ENTITY_TYPE_SECURITY_COVERAGE && this.toTypes.includes(toType);
      },
      isFilterable: true,
      toTypes: [ENTITY_TYPE_SECURITY_COVERAGE_RESULT],
    },
    objectLabel,
    objectMarking,
    createdBy,
    { ...objectOrganization, isFilterable: false },
  ],
  representative: (stix: StixSecurityCoverage) => {
    return stix.name;
  },
  converter_2_1: convertSecurityCoverageToStix,
  bundleResolver: securityCoverageStixBundle,
};

registerDefinition(SECURITY_COVERAGE_DEFINITION);
