import { type ModuleDefinition, registerDefinition } from '../../../schema/module';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../schema/general';
import { normalizeName } from '../../../schema/identifier';
import { createdAt, creators, coverageInformation, updatedAt } from '../../../schema/attribute-definition';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../securityCoverage-types';
import { createdBy, objectLabel, objectMarking, objectOrganization } from '../../../schema/stixRefRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_VULNERABILITY } from '../../../schema/stixDomainObject';
import { RELATION_HAS_COVERED } from '../../../schema/stixCoreRelationship';
import { REL_NEW } from '../../../database/stix';
import type { StoreEntity } from '../../../types/store';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../../../schema/stixCyberObservable';
import { ENTITY_TYPE_INDICATOR } from '../../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import {
  ATTRIBUTE_RESULT_OF,
  ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  INPUT_RESULT_OF,
  RELATION_RESULT_OF,
  type StixSecurityCoverageResult,
  type StoreEntitySecurityCoverageResult,
} from './securityCoverageResult-types';
import convertSecurityCoverageResultToStix from './securityCoverageResult-converter';

const SECURITY_COVERAGE_RESULT_DEFINITION: ModuleDefinition<StoreEntitySecurityCoverageResult, StixSecurityCoverageResult> = {
  type: {
    id: 'security-coverage-result',
    name: ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_SECURITY_COVERAGE_RESULT]: [{ src: 'name' }, { src: 'external_uri' }, { src: INPUT_RESULT_OF }],
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
      resultOf(data: object) {
        return (data as StoreEntity).standard_id;
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'external_uri', label: 'External URI', type: 'string', format: 'short', mandatoryType: 'no', editDefault: true, multiple: false, upsert: true, isFilterable: true },
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
        { name: ENTITY_HASHED_OBSERVABLE_ARTIFACT, type: REL_NEW },
        { name: ENTITY_TYPE_INDICATOR, type: REL_NEW },
      ],
    },
  ],
  relationsRefs: [
    {
      name: INPUT_RESULT_OF,
      type: 'ref',
      databaseName: RELATION_RESULT_OF,
      stixName: ATTRIBUTE_RESULT_OF,
      label: 'Security coverage',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: true,
      isRefExistingForTypes(this, fromType, toType) {
        return fromType === ENTITY_TYPE_SECURITY_COVERAGE_RESULT && this.toTypes.includes(toType);
      },
      isFilterable: true,
      toTypes: [ENTITY_TYPE_SECURITY_COVERAGE],
    },
    objectLabel,
    objectMarking,
    createdBy,
    { ...objectOrganization, isFilterable: false },
  ],
  representative: (stix: StixSecurityCoverageResult) => {
    return stix.name;
  },
  converter_2_1: convertSecurityCoverageResultToStix,
};

registerDefinition(SECURITY_COVERAGE_RESULT_DEFINITION);
