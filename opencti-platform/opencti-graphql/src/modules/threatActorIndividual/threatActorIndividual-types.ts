import type { StixDate, StixOpenctiExtension } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixContainer } from '../../types/stix-sdo';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

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
  extensions: {
    [STIX_EXT_OCTI]: StixThreatActorIndividualExtension
  }
}
