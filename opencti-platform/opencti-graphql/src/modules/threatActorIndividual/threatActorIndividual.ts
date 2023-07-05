import { v4 as uuid } from 'uuid';
import threatActorIndividualTypeDefs from './threatActorIndividual.graphql';
import { ENTITY_TYPE_THREAT_ACTOR } from '../../schema/general';
import { normalizeName } from '../../schema/identifier';
import { ModuleDefinition, registerDefinition } from '../../schema/module';
import { objectOrganization } from '../../schema/stixRefRelationship';
import type { StixThreatActorIndividual, StoreEntityThreatActorIndividual } from './threatActorIndividual-types';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from './threatActorIndividual-types';
import threatActorIndividualResolvers from './threatActorIndividual-resolvers';
import convertThreatActorIndividualToStix from './threatActorIndividual-converter';

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
      [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL]: () => uuid(),
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
  relations: [],
  relationsRefs: [
    objectOrganization,
  ],
  representative: (stix: StixThreatActorIndividual) => {
    return stix.name;
  },
  converter: convertThreatActorIndividualToStix
};
registerDefinition(THREAT_ACTOR_INDIVIDUAL_DEFINITION);
