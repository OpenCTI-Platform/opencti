import threatActorIndividualTypeDefs from './threatActorIndividual.graphql';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ENTITY_TYPE_THREAT_ACTOR } from '../../schema/general';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { ModuleDefinition, registerDefinition } from '../../schema/module';
import { objectOrganization } from '../../schema/stixRefRelationship';
import type { StixThreatActorIndividual, StoreEntityThreatActorIndividual } from './threatActorIndividual-types';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from './threatActorIndividual-types';
import threatActorIndividualResolvers from './threatActorIndividual-resolvers';
import convertThreatActorIndividualToStix from './threatActorIndividual-converter';
import {
  RELATION_ATTRIBUTED_TO, RELATION_COMPROMISES, RELATION_COOPERATES_WITH, RELATION_HOSTS, RELATION_IMPERSONATES,
  RELATION_LOCATED_AT, RELATION_OWNS, RELATION_PART_OF, RELATION_PARTICIPATES_IN,
  RELATION_TARGETS,
  RELATION_USES
} from '../../schema/stixCoreRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL, ENTITY_TYPE_VULNERABILITY
} from '../../schema/stixDomainObject';
import { REL_EXTENDED } from '../../database/stix';
import { ENTITY_TYPE_NARRATIVE } from '../narrative/narrative-types';
import { ENTITY_TYPE_CHANNEL } from '../channel/channel-types';
import { ENTITY_TYPE_EVENT } from '../event/event-types';

const THREAT_ACTOR_INDIVIDUAL_DEFINITION: ModuleDefinition<StoreEntityThreatActorIndividual, StixThreatActorIndividual> = {
  type: {
    id: 'threat-actor-individual',
    name: ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
    category: ENTITY_TYPE_THREAT_ACTOR
  },
  graphql: {
    schema: threatActorIndividualTypeDefs,
    resolver: threatActorIndividualResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL]: [{ src: NAME_FIELD }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    {
      name: 'threat_actor_types',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: true,
      upsert: false,
      label: 'Threat actor types'
    },
    { name: 'first_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'last_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'goals', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
    { name: 'roles', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
    { name: 'sophistication', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'resource_level', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'primary_motivation', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'secondary_motivations', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
    { name: 'personal_motivations', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
  ],
  relations: [
    { name: RELATION_USES,
      targets: [
        { name: ENTITY_TYPE_TOOL, type: REL_EXTENDED },
        { name: ABSTRACT_STIX_CYBER_OBSERVABLE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_MALWARE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_NARRATIVE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_CHANNEL, type: REL_EXTENDED },
        { name: ENTITY_TYPE_ATTACK_PATTERN, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_TARGETS,
      targets: [
        { name: ENTITY_TYPE_LOCATION_CITY, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_INDIVIDUAL, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_ORGANIZATION, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_POSITION, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_REGION, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_SECTOR, type: REL_EXTENDED },
        { name: ENTITY_TYPE_VULNERABILITY, type: REL_EXTENDED },
        { name: ENTITY_TYPE_EVENT, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_LOCATED_AT,
      targets: [
        { name: ENTITY_TYPE_LOCATION_CITY, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_POSITION, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_REGION, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_ATTRIBUTED_TO,
      targets: [
        { name: ENTITY_TYPE_IDENTITY_INDIVIDUAL, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_ORGANIZATION, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_IMPERSONATES,
      targets: [
        { name: ENTITY_TYPE_IDENTITY_INDIVIDUAL, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_ORGANIZATION, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_COMPROMISES,
      targets: [
        { name: ENTITY_TYPE_INFRASTRUCTURE, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_HOSTS,
      targets: [
        { name: ENTITY_TYPE_INFRASTRUCTURE, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_OWNS,
      targets: [
        { name: ENTITY_TYPE_INFRASTRUCTURE, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_PARTICIPATES_IN,
      targets: [
        { name: ENTITY_TYPE_CAMPAIGN, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_PART_OF,
      targets: [
        { name: ENTITY_TYPE_THREAT_ACTOR_GROUP, type: REL_EXTENDED },
      ]
    },
    { name: RELATION_COOPERATES_WITH,
      targets: [
        { name: ENTITY_TYPE_THREAT_ACTOR_GROUP, type: REL_EXTENDED },
      ]
    }
  ],
  relationsRefs: [
    objectOrganization,
  ],
  representative: (stix: StixThreatActorIndividual) => {
    return stix.name;
  },
  converter: convertThreatActorIndividualToStix
};
registerDefinition(THREAT_ACTOR_INDIVIDUAL_DEFINITION);
