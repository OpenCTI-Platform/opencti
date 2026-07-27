import React, { Suspense, FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useQueryLoadingWithLoadQuery } from 'src/utils/hooks/useQueryLoading';
import FilterIconButton from 'src/components/FilterIconButton';
import type { WidgetSavedFilterChipsQuery } from './__generated__/WidgetSavedFilterChipsQuery.graphql';
import type { ChipOwnProps } from '@mui/material';
import { removeFrontendIdAndEmptyFiltersFromFilterGroupObject } from 'src/utils/filters/filtersUtils';
import type { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import Chip from '@mui/material/Chip';
import { useFormatter } from 'src/components/i18n';
import { useTheme } from '@mui/material/styles';

const widgetSavedFilterChipsQuery = graphql`
  query WidgetSavedFilterChipsQuery($id: ID!) {
    savedFilter(id: $id) {
      id
      name
      filters
    }
  }
`;

interface WidgetSavedFilterChipsComponentProps {
  queryRef: PreloadedQuery<WidgetSavedFilterChipsQuery>;
  entityTypes?: string[];
  chipColor?: ChipOwnProps['color'];
}

const WidgetSavedFilterChipsComponent = ({
  queryRef,
  entityTypes,
  chipColor,
}: WidgetSavedFilterChipsComponentProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { savedFilter } = usePreloadedQuery(widgetSavedFilterChipsQuery, queryRef);

  // Parse defensively: savedFilter may be null (deleted/inaccessible)
  // and filters is a JSON string that could be malformed.
  let rawFilters: FilterGroup | null = null;
  if (savedFilter?.filters) {
    try {
      rawFilters = JSON.parse(savedFilter.filters) as FilterGroup;
    } catch {
      // malformed JSON – treat as unavailable
    }
  }

  const parsedFilters = removeFrontendIdAndEmptyFiltersFromFilterGroupObject(rawFilters);

  // not accessible, deleted, or invalid saved filter
  if (!parsedFilters) {
    return (
      <Chip
        label={t_i18n('Saved filter unavailable')}
        size="small"
        sx={{ marginLeft: 1, backgroundColor: theme.palette.warning.main, color: theme.palette.warning.contrastText }}
      />
    );
  }

  return (
    <FilterIconButton
      variant="small"
      filters={parsedFilters}
      entityTypes={entityTypes}
      chipColor={chipColor}
      redirection
    />
  );
};

interface WidgetSavedFilterChipsProps {
  filterId: string;
  entityTypes?: string[];
  chipColor?: ChipOwnProps['color'];
}

/**
 * Fetches a saved filter by ID and displays its content as read-only filter chips.
 * Uses FilterIconButton without helpers, making the chips non-editable
 */
const WidgetSavedFilterChips: FunctionComponent<WidgetSavedFilterChipsProps> = ({
  filterId,
  entityTypes,
  chipColor,
}) => {
  const [queryRef] = useQueryLoadingWithLoadQuery<WidgetSavedFilterChipsQuery>(
    widgetSavedFilterChipsQuery,
    { id: filterId },
  );

  if (!queryRef) return null;

  return (
    <Suspense fallback={null}>
      <WidgetSavedFilterChipsComponent
        queryRef={queryRef}
        entityTypes={entityTypes}
        chipColor={chipColor}
      />
    </Suspense>
  );
};

export default WidgetSavedFilterChips;
