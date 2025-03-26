import { buildStixDomain, cleanObject, convertObjectReferences, convertToStixDate } from '../../database/stix-2-1-converter';
import type { StixThreatActorIndividual, StoreEntityThreatActorIndividual } from './threatActorIndividual-types';
import { INPUT_BORN_IN, INPUT_ETHNICITY, INPUT_OBJECTS } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

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
      })
    }
  };
};

export default convertThreatActorIndividualToStix;
