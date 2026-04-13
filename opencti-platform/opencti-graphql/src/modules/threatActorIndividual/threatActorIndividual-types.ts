import type { StixOpenctiExtension } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixThreatActor } from '../../types/stix-2-1-sdo';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { Country, Measure } from '../../generated/graphql';
import type { RELATION_BORN_IN, RELATION_ETHNICITY } from '../../schema/stixRefRelationship';

export const ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL = 'Threat-Actor-Individual';

export interface BasicStoreEntityThreatActorIndividual extends BasicStoreEntity {
  name: string;
  description: string;
  aliases: string[];
  threat_actor_individual_types: string[];
  first_seen: Date;
  last_seen: Date;
  roles: string[];
  goals: string[];
  sophistication: string;
  resource_level: string;
  primary_motivations: string;
  secondary_motivations: string[];
  personal_motivations: string[];
  date_of_birth: Date;
  gender: string;
  job_title: string;
  marital_status: string;
  eye_color: string;
  hair_color: string;
  height: [Measure];
  weight: [Measure];
  [RELATION_BORN_IN]: string;
  [RELATION_ETHNICITY]: string;
}

export interface StoreEntityThreatActorIndividual extends StoreEntity {
  name: string;
  description: string;
  aliases: string[];
  threat_actor_individual_types: string[];
  first_seen: Date;
  last_seen: Date;
  roles: string[];
  goals: string[];
  sophistication: string;
  resource_level: string;
  primary_motivations: string;
  secondary_motivations: string[];
  personal_motivations: string[];
  date_of_birth: Date;
  gender: string;
  job_title: string;
  marital_status: string;
  eye_color: string;
  hair_color: string;
  height: [Measure];
  weight: [Measure];
  bornIn: Country;
  ethnicity: Country;
}

export interface StixThreatActorIndividualExtension extends StixOpenctiExtension {
  date_of_birth: Date;
  gender: string;
  job_title: string;
  marital_status: string;
  eye_color: string;
  hair_color: string;
  height: [Measure];
  weight: [Measure];
  born_in_ref: string;
  ethnicity_ref: string;
}

export interface StixThreatActorIndividual extends StixThreatActor {
  extensions: {
    [STIX_EXT_OCTI]: StixThreatActorIndividualExtension;
  };
  threat_acotor_individual_types: string[];
}
