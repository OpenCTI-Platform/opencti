import { REL_INDEX_PREFIX } from '../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { RELATION_INDICATES } from '../schema/stixCoreRelationship';

// eslint-disable-next-line import/prefer-default-export
export const GlobalFilters = {
  createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
  markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
  labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  indicates: `${REL_INDEX_PREFIX}${RELATION_INDICATES}.internal_id`,
};
