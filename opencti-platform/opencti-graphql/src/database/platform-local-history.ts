import { FilterMode, FilterOperator, type FilterGroup } from '../generated/graphql';
import { ENTITY_TYPE_DELETE_OPERATION } from '../modules/deleteOperation/deleteOperation-types';
import { ENTITY_TYPE_CURATION_PROPOSAL, ENTITY_TYPE_MERGE_RECORD } from '../modules/curation/curation-types';

// Every platform keeps its own trash, merge history and curation findings: they are never synchronized.
// They must stay internal objects: isStixExportableInStreamData keeps their events out of the stream synchronizers read.
export const PLATFORM_LOCAL_HISTORY_TYPES = [ENTITY_TYPE_DELETE_OPERATION, ENTITY_TYPE_MERGE_RECORD, ENTITY_TYPE_CURATION_PROPOSAL];

// The references these objects hold (markings, organizations, ...), left out when counting the knowledge relationships.
export const WITHOUT_PLATFORM_LOCAL_HISTORY_REFS: FilterGroup = {
  mode: FilterMode.And,
  filters: PLATFORM_LOCAL_HISTORY_TYPES.map((type) => ({
    mode: FilterMode.Or,
    key: ['elementWithTargetTypes'],
    values: [type],
    operator: FilterOperator.NotEq,
  })),
  filterGroups: [],
};
