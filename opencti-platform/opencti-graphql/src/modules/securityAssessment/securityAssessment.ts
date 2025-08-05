import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { normalizeName } from '../../schema/identifier';
import { createdAt, creators, updatedAt } from '../../schema/attribute-definition';
import {
  ATTRIBUTE_ASSESS,
  ENTITY_TYPE_SECURITY_ASSESSMENT,
  INPUT_ASSESS,
  RELATION_ASSESS,
  type StixSecurityAssessment,
  type StoreEntitySecurityAssessment
} from './securityAssessment-types';
import convertSecurityAssessmentToStix from './securityAssessment-converter';
import { objectOrganization, } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../schema/stixDomainObject';
import { securityAssessmentStixBundle } from './securityAssessment-domain';

const SECURITY_ASSESSMENT_DEFINITION: ModuleDefinition<StoreEntitySecurityAssessment, StixSecurityAssessment> = {
  type: {
    id: 'security-assessment',
    name: ENTITY_TYPE_SECURITY_ASSESSMENT,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_SECURITY_ASSESSMENT]: () => uuidv4()
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'periodicity', /* PT1S */ label: 'Periodicity', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    {
      name: 'latest_coverage',
      label: 'Latest coverage',
      type: 'object',
      format: 'nested',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: true,
      isFilterable: false,
      mappings: [
        { name: 'name', label: 'Coverage name', type: 'string', format: 'short', mandatoryType: 'external', upsert: true, editDefault: false, multiple: false, isFilterable: true },
        { name: 'score', label: 'Coverage score', type: 'numeric', mandatoryType: 'external', precision: 'float', upsert: true, editDefault: false, multiple: false, isFilterable: true },
      ]
    },
    creators,
    createdAt,
    updatedAt,
  ],
  relations: [],
  relationsRefs: [
    {
      name: INPUT_ASSESS,
      type: 'ref',
      databaseName: RELATION_ASSESS,
      stixName: ATTRIBUTE_ASSESS,
      label: 'Assess target',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: true,
      isRefExistingForTypes(this, fromType, toType) {
        return fromType === ENTITY_TYPE_SECURITY_ASSESSMENT && this.toTypes.includes(toType);
      },
      isFilterable: true,
      toTypes: [ENTITY_TYPE_THREAT_ACTOR_GROUP, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CONTAINER_REPORT],
    },
    { ...objectOrganization, isFilterable: false }
  ],
  representative: (stix: StixSecurityAssessment) => {
    return stix.name;
  },
  converter_2_1: convertSecurityAssessmentToStix,
  bundleResolver: securityAssessmentStixBundle
};

registerDefinition(SECURITY_ASSESSMENT_DEFINITION);
