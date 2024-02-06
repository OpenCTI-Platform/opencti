import { buildStixDomain, cleanObject, convertObjectReferences, convertToStixDate } from '../../database/stix-converter';
import { INPUT_BORN_IN, INPUT_ETHNICITY, INPUT_OBJECTS } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
const convertThreatActorIndividualToStix = (instance) => {
    var _a, _b, _c;
    const threatActor = buildStixDomain(instance);
    return Object.assign(Object.assign({}, threatActor), { name: instance.name, description: instance.description, threat_actor_types: instance.threat_actor_types, aliases: instance.aliases, first_seen: convertToStixDate(instance.first_seen), last_seen: convertToStixDate(instance.last_seen), roles: instance.roles, goals: instance.goals, sophistication: instance.sophistication, resource_level: instance.resource_level, primary_motivations: instance.primary_motivations, secondary_motivations: instance.secondary_motivations, personal_motivations: instance.personal_motivations, object_refs: ((_a = instance[INPUT_OBJECTS]) !== null && _a !== void 0 ? _a : []).map((m) => m.standard_id), extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, threatActor.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo', object_refs_inferred: convertObjectReferences(instance, true), date_of_birth: instance.date_of_birth, gender: instance.gender, job_title: instance.job_title, marital_status: instance.marital_status, eye_color: instance.eye_color, hair_color: instance.hair_color, height: instance.height, weight: instance.weight, born_in_ref: (_b = instance[INPUT_BORN_IN]) === null || _b === void 0 ? void 0 : _b.standard_id, ethnicity_ref: (_c = instance[INPUT_ETHNICITY]) === null || _c === void 0 ? void 0 : _c.standard_id }))
        } });
};
export default convertThreatActorIndividualToStix;
