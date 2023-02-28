import { buildRefRelationKey } from './general';
import {
  RELATION_CREATED_BY, RELATION_EXTERNAL_REFERENCE, RELATION_OBJECT,
  RELATION_OBJECT_ASSIGNEE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from './stixMetaRelationship';
import { RELATION_INDICATES } from './stixCoreRelationship';

export const stixDomainObjectOptions = {
  StixDomainObjectsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT, '*'),
    containedBy: buildRefRelationKey(RELATION_OBJECT, '*'),
    hasExternalReference: buildRefRelationKey(RELATION_EXTERNAL_REFERENCE),
    indicates: buildRefRelationKey(RELATION_INDICATES),
    creator: 'creator_id',
  },
  StixDomainObjectsOrdering: {}
};
