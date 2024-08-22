import type { JSONSchemaType } from 'ajv';
import { ENTITY_TYPE_THREAT_ACTOR } from '../../schema/general';
import { INNER_TYPE, NAME_FIELD, normalizeName } from '../../schema/identifier';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { bornIn, ethnicity, objectOrganization } from '../../schema/stixRefRelationship';
import type { StixThreatActorIndividual, StoreEntityThreatActorIndividual } from './threatActorIndividual-types';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from './threatActorIndividual-types';
import convertThreatActorIndividualToStix from './threatActorIndividual-converter';
import {
  RELATION_ATTRIBUTED_TO,
  RELATION_CITIZEN_OF,
  RELATION_COMPROMISES,
  RELATION_COOPERATES_WITH,
  RELATION_EMPLOYED_BY,
  RELATION_HOSTS,
  RELATION_IMPERSONATES,
  RELATION_KNOWN_AS,
  RELATION_LOCATED_AT,
  RELATION_NATIONAL_OF,
  RELATION_OWNS,
  RELATION_PART_OF,
  RELATION_PARTICIPATES_IN,
  RELATION_RESIDES_IN,
  RELATION_TARGETS,
  RELATION_USES
} from '../../schema/stixCoreRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY
} from '../../schema/stixDomainObject';
import { REL_BUILT_IN, REL_EXTENDED, REL_NEW } from '../../database/stix';
import { ENTITY_TYPE_NARRATIVE } from '../narrative/narrative-types';
import { ENTITY_TYPE_CHANNEL } from '../channel/channel-types';
import { ENTITY_TYPE_EVENT } from '../event/event-types';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_PERSONA } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../administrativeArea/administrativeArea-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';

interface Measures {
  measure: number | null
  date_seen: object | string | null
}

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
export const schemaMeasure: JSONSchemaType<Measures[]> = {
  type: 'array',
  items: {
    type: 'object',
    properties: {
      measure: { type: ['null', 'number'] },
      date_seen: { type: ['null', 'string', 'object'] },
    },
    required: ['measure', 'date_seen']
  }
};

const THREAT_ACTOR_INDIVIDUAL_DEFINITION: ModuleDefinition<StoreEntityThreatActorIndividual, StixThreatActorIndividual> = {
  type: {
    id: 'threat-actor-individual',
    name: ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
    category: ENTITY_TYPE_THREAT_ACTOR,
    aliased: true,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL]: [{ src: NAME_FIELD }, { src: INNER_TYPE }]
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
    { key: 'demographics', width: 6, label: 'Demographics' },
    { key: 'biographics', width: 6, label: 'Biographics' },
    { key: 'latestCreatedRelationships', width: 6, label: 'Latest created relationships' },
    { key: 'latestContainers', width: 6, label: 'Latest containers' },
    { key: 'externalReferences', width: 6, label: 'External references' },
    { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
    { key: 'notes', width: 12, label: 'Notes about this entity' },
  ],
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'threat_actor_types', label: 'Threat actor types', type: 'string', format: 'vocabulary', vocabularyCategory: 'threat_actor_individual_type_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: false, isFilterable: true },
    { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'goals', label: 'Goals', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'roles', label: 'Roles', type: 'string', format: 'vocabulary', vocabularyCategory: 'threat_actor_individual_role_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'sophistication', label: 'Sophistication', type: 'string', format: 'vocabulary', vocabularyCategory: 'threat_actor_individual_sophistication_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'resource_level', label: 'Resource level', type: 'string', format: 'vocabulary', vocabularyCategory: 'attack_resource_level_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'primary_motivation', label: 'Primary motivation', type: 'string', format: 'vocabulary', vocabularyCategory: 'attack_motivation_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'secondary_motivations', label: 'Secondary motivation', type: 'string', format: 'vocabulary', vocabularyCategory: 'attack_motivation_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'personal_motivations', label: 'Personal motivations', type: 'string', format: 'vocabulary', vocabularyCategory: 'attack_motivation_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'date_of_birth', label: 'Date of birth', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'gender', label: 'Gender', type: 'string', format: 'vocabulary', vocabularyCategory: 'gender_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'job_title', label: 'Job title', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'marital_status', label: 'Marital status', type: 'string', format: 'vocabulary', vocabularyCategory: 'marital_status_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'eye_color', label: 'Eye color', type: 'string', format: 'vocabulary', vocabularyCategory: 'eye_color_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hair_color', label: 'Hair color', type: 'string', format: 'vocabulary', vocabularyCategory: 'hair_color_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    {
      name: 'height',
      label: 'Height',
      type: 'object',
      format: 'nested',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: true,
      isFilterable: false,
      mappings: [
        { name: 'measure', label: 'Height measure', type: 'numeric', mandatoryType: 'external', upsert: true, precision: 'float', editDefault: false, multiple: false, isFilterable: true },
        { name: 'date_seen', label: 'Height measure date', type: 'date', mandatoryType: 'external', upsert: true, editDefault: false, multiple: false, isFilterable: true },
      ]
    },
    {
      name: 'weight',
      label: 'Weight',
      type: 'object',
      format: 'nested',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: true,
      isFilterable: false,
      mappings: [
        { name: 'measure', label: 'Weight measure', type: 'numeric', mandatoryType: 'external', upsert: true, precision: 'float', editDefault: false, multiple: false, isFilterable: true },
        { name: 'date_seen', label: 'Weight measure date', type: 'date', mandatoryType: 'external', upsert: true, editDefault: false, multiple: false, isFilterable: true }
      ]
    },
    { name: 'confidence', label: 'Confidence', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'revoked', label: 'Revoked', type: 'boolean', mandatoryType: 'no', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'lang', label: 'Lang', type: 'string', format: 'short', mandatoryType: 'no', editDefault: true, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [
    {
      name: RELATION_USES,
      targets: [
        { name: ENTITY_TYPE_TOOL, type: REL_BUILT_IN },
        { name: ENTITY_HASHED_OBSERVABLE_STIX_FILE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_MALWARE, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_NARRATIVE, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_CHANNEL, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_ATTACK_PATTERN, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_INFRASTRUCTURE, type: REL_BUILT_IN },
      ]
    },
    {
      name: RELATION_TARGETS,
      targets: [
        { name: ENTITY_TYPE_LOCATION_CITY, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_IDENTITY_INDIVIDUAL, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_IDENTITY_ORGANIZATION, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_IDENTITY_SYSTEM, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_POSITION, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_REGION, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_IDENTITY_SECTOR, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_VULNERABILITY, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_EVENT, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA, type: REL_BUILT_IN },
      ]
    },
    {
      name: RELATION_LOCATED_AT,
      targets: [
        { name: ENTITY_TYPE_LOCATION_CITY, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_POSITION, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_REGION, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA, type: REL_BUILT_IN },
      ]
    },
    {
      name: RELATION_ATTRIBUTED_TO,
      targets: [
        { name: ENTITY_TYPE_IDENTITY_INDIVIDUAL, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_IDENTITY_ORGANIZATION, type: REL_BUILT_IN },
      ]
    },
    {
      name: RELATION_IMPERSONATES,
      targets: [
        { name: ENTITY_TYPE_IDENTITY_INDIVIDUAL, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_IDENTITY_ORGANIZATION, type: REL_BUILT_IN },
      ]
    },
    {
      name: RELATION_COMPROMISES,
      targets: [
        { name: ENTITY_TYPE_INFRASTRUCTURE, type: REL_BUILT_IN },
      ]
    },
    {
      name: RELATION_HOSTS,
      targets: [
        { name: ENTITY_TYPE_INFRASTRUCTURE, type: REL_BUILT_IN },
      ]
    },
    {
      name: RELATION_OWNS,
      targets: [
        { name: ENTITY_TYPE_INFRASTRUCTURE, type: REL_BUILT_IN },
      ]
    },
    {
      name: RELATION_PARTICIPATES_IN,
      targets: [
        { name: ENTITY_TYPE_CAMPAIGN, type: REL_NEW },
      ]
    },
    {
      name: RELATION_PART_OF,
      targets: [
        { name: ENTITY_TYPE_THREAT_ACTOR_GROUP, type: REL_NEW },
        { name: ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL, type: REL_NEW },
      ]
    },
    {
      name: RELATION_COOPERATES_WITH,
      targets: [
        { name: ENTITY_TYPE_THREAT_ACTOR_GROUP, type: REL_NEW },
        { name: ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL, type: REL_NEW },
      ]
    },
    { name: RELATION_EMPLOYED_BY,
      targets: [
        { name: ENTITY_TYPE_THREAT_ACTOR_GROUP, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_ORGANIZATION, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_RESIDES_IN,
      targets: [
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_CITIZEN_OF,
      targets: [
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_NATIONAL_OF,
      targets: [
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_KNOWN_AS,
      targets: [
        { name: ENTITY_PERSONA, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_KNOWN_AS,
      targets: [
        { name: ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL, type: REL_EXTENDED },
      ]
    },
  ],
  relationsRefs: [
    objectOrganization,
    bornIn,
    ethnicity,
  ],
  representative: (stix: StixThreatActorIndividual) => {
    return stix.name;
  },
  converter: convertThreatActorIndividualToStix
};
registerDefinition(THREAT_ACTOR_INDIVIDUAL_DEFINITION);
