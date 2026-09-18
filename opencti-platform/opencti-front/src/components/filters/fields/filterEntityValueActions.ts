import { AutocompleteChangeReason } from '@mui/material';
import { Filter, FilterValue, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';

export const AUTOCOMPLETE_KEY_ACTIONS = {
  SELECT_OPTION: 'selectOption',
  REMOVE_OPTION: 'removeOption',
  CLEAR: 'clear',
  INPUT: 'input',
  RESET: 'reset',
} as const;

/** What a user gesture on the entity autocomplete means for the filter values. */
export type FilterValueChange
  = { type: 'clear' }
    | { type: 'add'; value: FilterValue }
    | { type: 'remove'; value: FilterValue }
    | { type: 'none' };

/**
 * Values currently held by the filter for the edited (sub)key. A subfilter (e.g. the
 * `relationship_type` part of `regardingOf`) stores its values in a child filter.
 */
export const getEditedValues = (filter?: Filter, subKey?: string): FilterValue[] => {
  const filterValues = filter?.values ?? [];
  if (!subKey) return filterValues;
  return filterValues.filter((filterValue) => filterValue && filterValue.key === subKey).at(0)?.values ?? [];
};

/**
 * Translates an Autocomplete change into a filter value change.
 *
 * Only single-value gestures are meaningful here: the component is driven one option at a
 * time, so a multi-value delta means the event did not come from a user selection.
 */
export const computeValueChange = (
  currentValues: FilterValue[],
  newValues: FilterValue[],
  reason: AutocompleteChangeReason,
): FilterValueChange => {
  if (reason === AUTOCOMPLETE_KEY_ACTIONS.CLEAR) return { type: 'clear' };
  if (reason !== AUTOCOMPLETE_KEY_ACTIONS.SELECT_OPTION && reason !== AUTOCOMPLETE_KEY_ACTIONS.REMOVE_OPTION) {
    return { type: 'none' };
  }
  const added = newValues.filter((v) => !currentValues.includes(v));
  if (added.length === 1) return { type: 'add', value: added[0] };
  const removed = currentValues.filter((v: FilterValue) => !newValues.includes(v));
  if (removed.length === 1) return { type: 'remove', value: removed[0] };
  return { type: 'none' };
};

/**
 * A disabled autocomplete still renders its options, but the last remaining value cannot be
 * touched: it is the value the surrounding editor depends on (e.g. the relationship type of
 * a composite filter).
 */
export const isChangeBlocked = (
  change: FilterValueChange,
  currentValues: FilterValue[],
  disabled: boolean,
): boolean => {
  if (!disabled || currentValues.length !== 1) return false;
  if (change.type === 'add') return currentValues.includes(change.value);
  // 'clear' drops the same sole value a 'remove' would: blocked the same way.
  return change.type === 'remove' || change.type === 'clear';
};

const applyRepresentationChange = (
  helpers: handleFilterHelpers | undefined,
  filter: Filter | undefined,
  subKey: string,
  checked: boolean,
  value: FilterValue,
) => {
  const childFilters = (filter?.values ?? []).filter((val) => val.key === subKey) as Filter[];
  const childFilter = childFilters.length > 0 ? childFilters[0] : undefined;
  const alreadySelectedValues = childFilter?.values ?? [];
  let representationToAdd;
  if (checked) {
    // the representation to add = the former values + the added value
    representationToAdd = { key: subKey, values: [...alreadySelectedValues, value] };
  } else {
    const cleanedValues = alreadySelectedValues.filter((val) => val !== value);
    // the representation to add = the former values - the removed value
    representationToAdd = cleanedValues.length > 0 ? { key: subKey, values: cleanedValues } : undefined;
  }
  helpers?.handleChangeRepresentationFilter(filter?.id ?? '', childFilter, representationToAdd);
};

/** Pushes a computed change to the shared filter state. */
export const applyValueChange = (
  change: FilterValueChange,
  {
    helpers,
    filter,
    subKey,
  }: { helpers?: handleFilterHelpers; filter?: Filter; subKey?: string },
) => {
  if (change.type === 'none') return;
  if (change.type === 'clear') {
    if (subKey) {
      const childFilters = (filter?.values ?? []).filter((val) => val.key === subKey) as Filter[];
      const childFilter = childFilters.length > 0 ? childFilters[0] : undefined;
      helpers?.handleChangeRepresentationFilter(filter?.id ?? '', childFilter, undefined);
    } else {
      helpers?.handleReplaceFilterValues(filter?.id ?? '', []);
    }
    return;
  }
  const checked = change.type === 'add';
  if (subKey) {
    applyRepresentationChange(helpers, filter, subKey, checked, change.value);
  } else if (checked) {
    helpers?.handleAddRepresentationFilter(filter?.id ?? '', change.value);
  } else {
    helpers?.handleRemoveRepresentationFilter(filter?.id ?? '', change.value);
  }
};
