import {
  buildStixDomain,
  cleanObject,
  convertObjectReferences,
  convertToStixDate
} from '../../database/stix-converter';
import type { StixThreatActorIndividual, StoreEntityThreatActorIndividual } from './threatActorIndividual-types';
import { INPUT_BORN_IN, INPUT_CREATED_BY, INPUT_OBJECTS } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

const convertThreatActorIndividualToStix = (instance: StoreEntityThreatActorIndividual): StixThreatActorIndividual => {
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
    x_mcas_date_of_birth: instance.x_mcas_date_of_birth,
    x_mcas_ethnicity: instance.x_mcas_ethnicity,
    x_mcas_gender: instance.x_mcas_gender,
    x_mcas_job_title: instance.x_mcas_job_title,
    x_mcas_marital_status: instance.x_mcas_marital_status,
    x_mcas_nationality: instance.x_mcas_nationality,
    x_mcas_eye_color: instance.x_mcas_eye_color,
    x_mcas_hair_color: instance.x_mcas_hair_color,
    x_mcas_height: instance.x_mcas_height,
    x_mcas_weight: instance.x_mcas_weight,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    born_in_ref: instance[INPUT_BORN_IN]?.standard_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...threatActor.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
        object_refs_inferred: convertObjectReferences(instance, true),
        eye_color: instance.eye_color,
      })
    }
  };
};

export default convertThreatActorIndividualToStix;
