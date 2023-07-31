import type { DateTime } from '@elastic/elasticsearch/lib/api/types';
import type { StixDate, StixOpenctiExtension } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixContainer } from '../../types/stix-sdo';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { Country, EyeColor, Gender, HairColor, HeightTupleInputValues, MaritalStatus, Origin, WeightTupleInputValues } from '../../generated/graphql';
import type { RELATION_BORN_IN } from '../../schema/stixRefRelationship';

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
  eye_color: string
  x_mcas_date_of_birth: DateTime
  x_mcas_ethnicity: Origin
  x_mcas_gender: Gender
  x_mcas_job_title: string
  x_mcas_marital_status: MaritalStatus
  x_mcas_nationality: Origin
  x_mcas_eye_color: EyeColor
  x_mcas_hair_color: HairColor
  x_mcas_height: [HeightTupleInputValues]
  x_mcas_weight: [WeightTupleInputValues]
  [RELATION_BORN_IN]: string
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
  eye_color: string
  x_mcas_date_of_birth: DateTime
  x_mcas_ethnicity: Origin
  x_mcas_gender: Gender
  x_mcas_job_title: string
  x_mcas_marital_status: MaritalStatus
  x_mcas_nationality: Origin
  x_mcas_eye_color: EyeColor
  x_mcas_hair_color: HairColor
  x_mcas_height: [HeightTupleInputValues]
  x_mcas_weight: [WeightTupleInputValues]
  bornIn: Country
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
  x_mcas_date_of_birth: DateTime
  x_mcas_ethnicity: Origin
  x_mcas_gender: Gender
  x_mcas_job_title: string
  x_mcas_marital_status: MaritalStatus
  x_mcas_nationality: Origin
  x_mcas_eye_color: EyeColor
  x_mcas_hair_color: HairColor
  x_mcas_height: [HeightTupleInputValues]
  x_mcas_weight: [WeightTupleInputValues]
  born_in_ref: string
  extensions: {
    [STIX_EXT_OCTI]: StixThreatActorIndividualExtension
  }
}
