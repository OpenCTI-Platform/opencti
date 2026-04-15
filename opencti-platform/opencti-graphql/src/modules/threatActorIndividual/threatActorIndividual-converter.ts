import { buildStixDomain } from '../../database/stix-2-1-converter';
import type { StixThreatActorIndividual, StoreEntityThreatActorIndividual } from './threatActorIndividual-types';
import type { StixThreatActor } from '../../types/stix-2-0-sdo';
import { INPUT_BORN_IN, INPUT_ETHNICITY, INPUT_OBJECTS } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { assertType, cleanObject, convertObjectReferences, convertToStixDate } from '../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from './threatActorIndividual-types';
import type { StoreEntity } from '../../types/store';

export const convertThreatActorIndividualToStix_2_1 = (instance: StoreEntityThreatActorIndividual): StixThreatActorIndividual => {
  const threatActor = buildStixDomain(instance);
  return {
    ...threatActor,
    name: instance.name,
    description: instance.description,
    threat_actor_types: instance.threat_actor_types,
    aliases: instance.aliases,
    first_seen: convertToStixDate(instance.first_seen),
    last_seen: convertToStixDate(instance.last_seen),
    roles: instance.roles,
    goals: instance.goals,
    sophistication: instance.sophistication,
    resource_level: instance.resource_level,
    primary_motivations: instance.primary_motivations,
    secondary_motivations: instance.secondary_motivations,
    personal_motivations: instance.personal_motivations,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...threatActor.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
        object_refs_inferred: convertObjectReferences(instance, true),
        date_of_birth: instance.date_of_birth,
        gender: instance.gender,
        job_title: instance.job_title,
        marital_status: instance.marital_status,
        eye_color: instance.eye_color,
        hair_color: instance.hair_color,
        height: instance.height,
        weight: instance.weight,
        born_in_ref: instance[INPUT_BORN_IN]?.standard_id,
        ethnicity_ref: instance[INPUT_ETHNICITY]?.standard_id,
      }),
    },
  };
};

export const convertThreatActorIndividualToStix_2_0 = (instance: StoreEntity): StixThreatActor & {
  date_of_birth: string | undefined;
  gender: string;
  job_title: string;
  marital_status: string;
  eye_color: string;
  hair_color: string;
  height: any[];
  weight: any[];
  born_in_ref: string;
  ethnicity_ref: string;
} => {
  assertType(ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL, instance.entity_type);
  const threatActorIndividual = instance as StoreEntityThreatActorIndividual;
  const threatActor = buildStixDomain2(instance);
  return {
    ...threatActor,
    name: instance.name,
    description: instance.description,
    threat_actor_types: instance.threat_actor_types,
    aliases: instance.aliases,
    first_seen: convertToStixDate(instance.first_seen),
    last_seen: convertToStixDate(instance.last_seen),
    roles: instance.roles,
    goals: instance.goals,
    sophistication: instance.sophistication,
    resource_level: instance.resource_level,
    primary_motivation: (instance as any).primary_motivation ?? threatActorIndividual.primary_motivations,
    secondary_motivations: instance.secondary_motivations,
    personal_motivations: instance.personal_motivations,
    date_of_birth: convertToStixDate(threatActorIndividual.date_of_birth),
    gender: threatActorIndividual.gender,
    job_title: threatActorIndividual.job_title,
    marital_status: threatActorIndividual.marital_status,
    eye_color: threatActorIndividual.eye_color,
    hair_color: threatActorIndividual.hair_color,
    height: threatActorIndividual.height,
    weight: threatActorIndividual.weight,
    born_in_ref: threatActorIndividual[INPUT_BORN_IN]?.standard_id,
    ethnicity_ref: threatActorIndividual[INPUT_ETHNICITY]?.standard_id,
  };
};
