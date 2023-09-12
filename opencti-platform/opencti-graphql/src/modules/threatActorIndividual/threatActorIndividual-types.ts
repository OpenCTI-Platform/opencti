import type { DateTime } from '@elastic/elasticsearch/lib/api/types';
import type { StixDate, StixOpenctiExtension } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixContainer } from '../../types/stix-sdo';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { Country, HeightTupleInputValues, WeightTupleInputValues } from '../../generated/graphql';
import type { RELATION_BORN_IN, RELATION_ETHNICITY, RELATION_NATIONALITY } from '../../schema/stixRefRelationship';

export const ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL = 'Threat-Actor-Individual';

export interface BasicStoreEntityThreatActorIndividual extends BasicStoreEntity {
  name: string
  description: string
  aliases: string[]
  threat_actor_types: string[]
  first_seen: Date
  last_seen: Date
  roles: string[]
  goals: string[]
  sophistication: string
  resource_level: string
  primary_motivations: string
  secondary_motivations: string[]
  personal_motivations: string[]
  date_of_birth: DateTime
  gender: string
  job_title: string
  marital_status: string
  eye_color: string
  hair_color: string
  height: [HeightTupleInputValues]
  weight: [WeightTupleInputValues]
  [RELATION_BORN_IN]: string
  [RELATION_NATIONALITY]: string
  [RELATION_ETHNICITY]: string
}

export interface StoreEntityThreatActorIndividual extends StoreEntity {
  name: string
  description: string
  aliases: string[]
  threat_actor_types: string[]
  first_seen: Date
  last_seen: Date
  roles: string[]
  goals: string[]
  sophistication: string
  resource_level: string
  primary_motivations: string
  secondary_motivations: string[]
  personal_motivations: string[]
  date_of_birth: DateTime
  gender: string
  job_title: string
  marital_status: string
  eye_color: string
  hair_color: string
  height: [HeightTupleInputValues]
  weight: [WeightTupleInputValues]
  bornIn: Country
  nationality: Country
  ethnicity: Country
}

export interface StixThreatActorIndividualExtension extends StixOpenctiExtension {
  eye_color: string
}

export interface StixThreatActorIndividual extends StixContainer {
  name: string
  description: string
  aliases: string[]
  threat_actor_types: string[]
  first_seen: StixDate
  last_seen: StixDate
  roles: string[]
  goals: string[]
  sophistication: string
  resource_level: string
  primary_motivations: string
  secondary_motivations: string[]
  personal_motivations: string[]
  date_of_birth: DateTime
  gender: string
  job_title: string
  marital_status: string
  eye_color: string
  hair_color: string
  height: [HeightTupleInputValues]
  weight: [WeightTupleInputValues]
  born_in_ref: string
  nationality_ref: string
  ethnicity_ref: string
  extensions: {
    [STIX_EXT_OCTI]: StixThreatActorIndividualExtension
  }
}
