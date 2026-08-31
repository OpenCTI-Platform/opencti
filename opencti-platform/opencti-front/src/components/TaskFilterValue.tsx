import * as R from 'ramda';
import React from 'react';
import { Chip } from '@filigran/design-system';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { filterValuesContentQuery } from './FilterValuesContent';
import { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import { useFormatter } from './i18n';
import { entityTypesFilters, filterOperatorsWithIcon, useFilterDefinition } from '../utils/filters/filtersUtils';
import { displayEntityTypeForTranslation, truncate } from '../utils/String';
import ImbricatedFilterGroupDisplay from './filters/ImbricatedFilterGroupDisplay';
import { FilterGroup } from '../utils/filters/filtersHelpers-types';

/**
 * The task detail was the last screen mixing shapes: a MUI pill here next to the library Chip
 * everywhere else on the same block.
 */
const CHIP_STYLE = { margin: '5px 10px 5px 0' };

// Text twin of `convertOperatorToIcon`, which returns JSX and cannot go in a label.
const OPERATOR_SYMBOL: Record<string, string> = {
  lt: '<',
  lte: '≤',
  gt: '>',
  gte: '≥',
  eq: '=',
  not_eq: '≠',
};

const TaskFilterValue = ({
  filters,
  queryRef,
  entityTypes,
}: {
  filters: FilterGroup;
  queryRef: PreloadedQuery<FilterValuesContentQuery>;
  entityTypes?: string[];
}) => {
  const { t_i18n } = useFormatter();
  const { filtersRepresentatives } = usePreloadedQuery<FilterValuesContentQuery>(
    filterValuesContentQuery,
    queryRef,
  );
  const filtersRepresentativesMap = new Map(
    (filtersRepresentatives ?? []).map((n) => [n?.id, n]),
  );
  const globalFilterMode = t_i18n(filters.mode.toUpperCase());
  return (
    <>
      {(filters.filters ?? []).map((currentFilter) => {
        const filterDefinition = useFilterDefinition(currentFilter.key, entityTypes);
        const label = truncate(
          t_i18n(filterDefinition?.label ?? currentFilter.key),
          20,
        );
        // `filterValue` is a hook, so it cannot run per value here; these are the
        // branches of it that this screen actually hits.
        const formatValue = (raw: string) => {
          if (entityTypesFilters.includes(currentFilter.key)) {
            return raw === 'all' ? t_i18n('entity_All') : t_i18n(displayEntityTypeForTranslation(raw));
          }
          if (filterDefinition?.type === 'enum' || filterDefinition?.type === 'boolean') {
            return t_i18n(raw);
          }
          if (currentFilter.key === 'relationship_type' || currentFilter.key === 'type') {
            return t_i18n(`relationship_${raw}`);
          }
          return raw;
        };
        const operator = currentFilter.operator ?? 'eq';
        const isOperatorDisplayed = filterOperatorsWithIcon.includes(operator);
        if (currentFilter.key === 'regardingOf') {
          const sortedFilterValues = [...currentFilter.values].sort((a, b) => -a.key.localeCompare(b.key)); // display type first, then id
          // The nested group used to live inside this chip's label; it renders as
          // a sibling now, so every chip on the row keeps the same box.
          return (
            <span key={currentFilter.key}>
              <Chip label={`${label}:`} style={CHIP_STYLE} />
              <TaskFilterValue filters={{ mode: 'and', filters: sortedFilterValues, filterGroups: [] }} queryRef={queryRef} />
            </span>
          );
        }
        const values = currentFilter.values.map(
          (o) => formatValue(`${filtersRepresentativesMap.get(o)?.value ?? o}`),
        );
        const localFilterMode = t_i18n((currentFilter.mode ?? 'or').toUpperCase());
        const joined = truncate(values.join(` ${localFilterMode} `), 40);
        const head = isOperatorDisplayed
          ? `${label} ${OPERATOR_SYMBOL[operator] ?? ''}`.trim()
          : `${label} ${t_i18n(operator)}`.trim();
        return (
          <span key={currentFilter.key}>
            <Chip
              label={values.length > 0 ? `${head} ${joined}` : head}
              style={CHIP_STYLE}
            />
            {R.last(filters.filters)?.key !== currentFilter.key && (
              <Chip label={globalFilterMode} style={CHIP_STYLE} />
            )}
          </span>
        );
      })}
      {filters.filterGroups
        && filters.filterGroups.length > 0 && (
        <ImbricatedFilterGroupDisplay
          filtersRepresentativesMap={filtersRepresentativesMap}
          filterObj={filters}
          filterMode={filters.mode}
          filterStyle={CHIP_STYLE}
        />
      )}
    </>
  );
};

export default TaskFilterValue;
