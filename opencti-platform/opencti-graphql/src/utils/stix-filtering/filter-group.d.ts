export type FilterMode = 'AND' | 'OR';
export type FilterOperator = 'eq' | 'not_eq' | 'lt' | 'lte' | 'gt' | 'gte' | 'nil' | 'not_nil';

export type Filter = {
  // multiple keys possible (internal use, in streams it's not possible)
  // TODO: it should probably be named keys, but that's another story.
  key: string[] // name, entity_type, etc
  mode: FilterMode
  values: string[]
  operator: FilterOperator
};

export type FilterGroup = {
  mode: FilterMode
  filters: Filter[]
  filterGroups: FilterGroup[]
};
