import { head, last, toPairs } from 'ramda';
import { Filter, FilterGroup } from './filtersHelpers-types';

// --- convert filters in the old format (before 5.12) to the new one

export const convertFiltersFromOldFormat = (filters: string): FilterGroup => {
  const filterKeysConvertor = new Map([
    ['labelledBy', 'objectLabel'],
    ['markedBy', 'objectMarking'],
    ['objectContains', 'objects'],
    ['killChainPhase', 'killChainPhases'],
    ['assigneeTo', 'objectAssignee'],
    ['participant', 'objectParticipant'],
    ['creator', 'creator_id'],
    ['hasExternalReference', 'externalReferences'],
    ['hashes_MD5', 'hashes.MD5'],
    ['hashes_SHA1', 'hashes.SHA-1'],
    ['hashes_SHA256', 'hashes.SHA-256'],
    ['hashes_SHA512', 'hashes.SHA-512'],
  ]);
  const newFiltersContent: Filter[] = [];
  const newFilterGroupsContent: FilterGroup[] = [];
  toPairs(JSON.parse(filters)).forEach((pair) => {
    let key: string = head(pair);
    const values: { id: string | null; value: string }[] = last(pair);
    const valIds = values.map((v) => v.id);
    let operator = 'eq';
    let mode = 'or';
    // handle operators contained in the key
    if (key.endsWith('start_date') || key.endsWith('_gt')) {
      key = key.replace('_start_date', '').replace('_gt', '');
      operator = 'gt';
    } else if (key.endsWith('end_date') || key.endsWith('_lt')) {
      key = key.replace('_end_date', '').replace('_lt', '');
      operator = 'lt';
    } else if (key.endsWith('_lte')) {
      key = key.replace('_lte', '');
      operator = 'lte';
    } else if (key.endsWith('_not_eq')) {
      key = key.replace('_not_eq', '');
      operator = 'not_eq';
      mode = 'and';
    }
    // change renamed keys
    if (filterKeysConvertor.get(key)) {
      key = filterKeysConvertor.get(key) as string;
    }
    if (valIds.includes(null)) { // values cannot contains 'null' anymore, new nil operator
      const nilOperator = (operator === 'not_eq') ? 'not_nil' : 'nil'; // replace the operator
      if (valIds.length === 1) { // if there is only 'null' in values
        newFiltersContent.push({ key, values: [], operator: nilOperator, mode }); // replace by a filter with nil and values = []
      } else { // if there is other values
        newFilterGroupsContent.push(
          {
            mode,
            filters: [
              { key, values: valIds.filter((id) => id !== null) as string[], operator, mode }, // remove null id
              { key, values: [], operator: nilOperator, mode }, // create a filter for the former null id
            ],
            filterGroups: [],
          },
        );
      }
    } else {
      newFiltersContent.push({ key, values: valIds as string[], operator, mode });
    }
  });
  return {
    mode: 'and',
    filters: newFiltersContent,
    filterGroups: newFilterGroupsContent,
  };
};
