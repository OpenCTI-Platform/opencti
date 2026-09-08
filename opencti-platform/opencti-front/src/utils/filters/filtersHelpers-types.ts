// usually string, but can be a combined filter like regardingOf
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type FilterValue = any;

export type FilterGroup = {
  // FRONTEND-ONLY stable uuid, used to address a group in a nested filter tree (add a filter in it,
  // switch its and/or mode, delete it). It is never accepted by the backend `FilterGroup` input:
  // every serialization path goes through stripFilterIds() which removes it recursively.
  id?: string;
  mode: string;
  filters: Filter[];
  filterGroups: FilterGroup[];
};

// TODO: import from graphql generated types
export type Filter = {
  id?: string;
  key: string; // key is a string in front
  values: FilterValue[];
  operator?: string;
  mode?: string;
};

export type HandleOperatorFilter = (
  id: string,
  op: string,
) => void;

export interface handleFilterHelpers {
  handleSwitchGlobalMode: () => void;
  handleSwitchLocalMode: (filter: Filter) => void;
  handleRemoveRepresentationFilter: (id: string, valueId: string | Filter | undefined | null) => void;
  handleRemoveFilterById: (id: string) => void;
  handleChangeOperatorFilters: HandleOperatorFilter;
  handleAddSingleValueFilter: (id: string, valueId?: string) => void;
  handleAddRepresentationFilter: (id: string, valueId: string | null) => void;
  handleAddFilterWithEmptyValue: (filter: Filter) => void;
  handleClearAllFilters: (filters?: Filter[]) => void;
  getLatestAddFilterId: () => string | undefined;
  handleChangeRepresentationFilter: (id: string, oldValue: FilterValue, newValue: FilterValue) => void;
  handleReplaceFilterValues: (id: string, values: string[] | FilterGroup[]) => void;
}
