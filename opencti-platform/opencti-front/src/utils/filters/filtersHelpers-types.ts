// usually string, but can be a combined filter like regardingOf
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type FilterValue = any;

export type FilterGroup = {
  mode: string;
  filters: Filter[];
  filterGroups: FilterGroup[];
};

export type FilterGroupWithArrayKeys = {
  mode: string;
  filters: FilterWithArrayKeys[];
  filterGroups: FilterGroupWithArrayKeys[];
};

// TODO: import from graphql generated types
export type Filter = {
  id?: string;
  key: string; // key is a string in front, except in Bulk Search (array of keys, specify isMultiKeysFilter to true in DataTable to handle this)
  values: FilterValue[];
  operator?: string;
  mode?: string;
};

export type FilterWithArrayKeys = {
  id?: string;
  key: string | string[];
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
