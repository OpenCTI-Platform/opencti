import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { normalizeName } from '../../schema/identifier';
import { createdAt, creators, coverageInformation, updatedAt } from '../../schema/attribute-definition';
import {
  ATTRIBUTE_COVERED,
  ENTITY_TYPE_SECURITY_COVERAGE,
  INPUT_COVERED,
  RELATION_COVERED,
  type StixSecurityCoverage,
  type StoreEntitySecurityCoverage
} from './securityCoverage-types';
import convertSecurityCoverageToStix from './securityCoverage-converter';
import { createdBy, objectLabel, objectMarking, objectOrganization, } from '../../schema/stixRefRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_VULNERABILITY
} from '../../schema/stixDomainObject';
import { securityCoverageStixBundle } from './securityCoverage-domain';
import { RELATION_HAS_COVERED } from '../../schema/stixCoreRelationship';
import { REL_NEW } from '../../database/stix';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import type { StoreEntity } from '../../types/store';

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
    { name: 'coverage_periodicity', /* PT1S */ label: 'Periodicity', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'coverage_last_result', label: 'Last coverage', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'coverage_valid_from', label: 'Valid coverage from', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'coverage_valid_to', label: 'Valid coverage to', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    coverageInformation,
    creators,
    createdAt,
    updatedAt,
  ],
  relations: [
    {
      name: RELATION_HAS_COVERED,
      targets: [
        { name: ENTITY_TYPE_ATTACK_PATTERN, type: REL_NEW },
        { name: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, type: REL_NEW },
        { name: ENTITY_TYPE_VULNERABILITY, type: REL_NEW },
      ]
    },
  ],
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
      toTypes: [ENTITY_TYPE_THREAT_ACTOR_GROUP, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CONTAINER_REPORT],
    },
    objectLabel,
    objectMarking,
    createdBy,
    { ...objectOrganization, isFilterable: false }
  ],
  representative: (stix: StixSecurityCoverage) => {
    return stix.name;
  },
  converter_2_1: convertSecurityCoverageToStix,
  bundleResolver: securityCoverageStixBundle
};

registerDefinition(SECURITY_COVERAGE_DEFINITION);
