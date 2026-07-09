import React, { Suspense, FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useQueryLoadingWithLoadQuery } from 'src/utils/hooks/useQueryLoading';
import FilterIconButton from 'src/components/FilterIconButton';
import type { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import type { WidgetSavedFilterChipsQuery } from './__generated__/WidgetSavedFilterChipsQuery.graphql';
import type { ChipOwnProps } from '@mui/material';

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
  const { savedFilter } = usePreloadedQuery(widgetSavedFilterChipsQuery, queryRef);

  if (!savedFilter?.filters) return null;

  const parsedFilters: FilterGroup = JSON.parse(savedFilter.filters);

  return (
    <FilterIconButton
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
