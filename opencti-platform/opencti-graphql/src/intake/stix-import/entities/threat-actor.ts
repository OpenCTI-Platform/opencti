import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { asStr, getAttributeInExtension } from '../utils';
import type { Kwargs } from '../kwargs';
import { importThreatActorGroup } from './threat-actor-group';
import { importThreatActorIndividual } from './threat-actor-individual';

// pycti opencti_threat_actor.py:import_from_stix2: the group or individual importer, by the
// OpenCTI type, else by the resource level, else a group
export const importThreatActor = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  let type: string;
  if ('x_opencti_type' in object) {
    type = asStr(object.x_opencti_type, 'lower').toLowerCase();
  } else if (getAttributeInExtension('type', object) !== null) {
    type = asStr(getAttributeInExtension('type', object), 'lower').toLowerCase();
  } else if ('resource_level' in object && asStr(object.resource_level, 'lower').toLowerCase() === 'individual') {
    type = 'threat-actor-individual';
  } else {
    type = 'threat-actor-group';
  }
  if (type === 'threat-actor-individual') {
    return importThreatActorIndividual(context, object, extras, update);
  }
  return importThreatActorGroup(context, object, extras, update);
};
