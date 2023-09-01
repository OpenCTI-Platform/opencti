import type { RelationshipMappings } from './stix';
import { REL_NEW } from './stix';
import {
  ENTITY_TYPE_CONTAINER,
  ENTITY_TYPE_IDENTITY,
  INPUT_ASSIGNEE,
  INPUT_CREATED_BY,
  INPUT_EXTERNAL_REFS,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_OBJECTS,
  INPUT_PARTICIPANT
} from '../schema/general';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION
} from '../schema/stixMetaObject';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { schemaTypesMapping } from '../domain/stixRelationship';

export const stixRefRelationshipsMapping: RelationshipMappings = {
  [`*_${ENTITY_TYPE_IDENTITY}`]: [
    { name: INPUT_CREATED_BY, type: REL_NEW }
  ],
  [`*_${ENTITY_TYPE_MARKING_DEFINITION}`]: [
    { name: INPUT_MARKINGS, type: REL_NEW }
  ],
  [`*_${ENTITY_TYPE_CONTAINER}`]: [
    { name: INPUT_OBJECTS, type: REL_NEW }
  ],
  [`*_${ENTITY_TYPE_USER}`]: [
    { name: INPUT_ASSIGNEE, type: REL_NEW }
  ],
  [`*_${ENTITY_TYPE_USER}`]: [
    { name: INPUT_PARTICIPANT, type: REL_NEW }
  ],
  [`*_${ENTITY_TYPE_LABEL}`]: [
    { name: INPUT_LABELS, type: REL_NEW }
  ],
  [`*_${ENTITY_TYPE_EXTERNAL_REFERENCE}`]: [
    { name: INPUT_EXTERNAL_REFS, type: REL_NEW }
  ],
  [`*_${ENTITY_TYPE_KILL_CHAIN_PHASE}`]: [
    { name: INPUT_KILLCHAIN, type: REL_NEW }
  ],
};

export const schemaRelationsRefTypesMapping = () => {
  return schemaTypesMapping(stixRefRelationshipsMapping);
};
