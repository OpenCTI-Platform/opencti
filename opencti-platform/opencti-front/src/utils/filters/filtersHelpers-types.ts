// usually string, but can be a combined filter like regardingOf
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type FilterValue = any;

export type FilterGroup = {
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
  handleRemoveRepresentationFilter: (id: string, valueId: string) => void;
  handleRemoveFilterById: (id: string) => void;
  handleChangeOperatorFilters: HandleOperatorFilter;
  handleAddSingleValueFilter: (id: string, valueId?: string) => void;
  handleAddRepresentationFilter: (id: string, valueId: string) => void;
  handleAddFilterWithEmptyValue: (filter: Filter) => void;
  handleClearAllFilters: (filters?: Filter[]) => void;
  getLatestAddFilterId: () => string | undefined;
  handleChangeRepresentationFilter: (id: string, oldValue: FilterValue, newValue: FilterValue) => void;
}
