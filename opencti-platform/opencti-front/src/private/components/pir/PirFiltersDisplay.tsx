import React from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Chip, { ChipProps } from '@mui/material/Chip';
import { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { FilterValuesContentQuery } from '../../../components/__generated__/FilterValuesContentQuery.graphql';
import { filterValuesContentQuery } from '../../../components/FilterValuesContent';
import { GqlFilterGroup, removeIdFromFilterGroupObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';

interface PirFiltersDisplayComponentProps {
  size?: ChipProps['size']
  filterGroup: FilterGroup
  queryRef: PreloadedQuery<FilterValuesContentQuery>
}

const PirFiltersDisplayComponent = ({
  queryRef,
  filterGroup,
  size = 'medium',
}: PirFiltersDisplayComponentProps) => {
  const { t_i18n } = useFormatter();
  const { filtersRepresentatives } = usePreloadedQuery(filterValuesContentQuery, queryRef);
  const { filters } = filterGroup;

  const relationship = filters.find((filter) => filter.key.includes('entity_type'))?.values[0];
  const targetId = filters.find((filter) => filter.key.includes('toId'))?.values[0];
  const target = filtersRepresentatives.find((rep) => rep.id === targetId)?.value;

  return (
    <Chip
      size={size}
      sx={{ textTransform: 'capitalize', borderRadius: 1 }}
      label={`${t_i18n(`relationship_${relationship}`)} ${target ?? t_i18n('Unknown')}`}
    />
  );
};

type ShortDisplayFilterProps = Omit<PirFiltersDisplayComponentProps, 'queryRef'>;

const PirFiltersDisplay = (props: ShortDisplayFilterProps) => {
  const filters = removeIdFromFilterGroupObject(props.filterGroup);
  if (!filters) return null;

  const filtersRepresentativesQueryRef = useQueryLoading<FilterValuesContentQuery>(
    filterValuesContentQuery,
    { filters: filters as unknown as GqlFilterGroup },
  );

  return filtersRepresentativesQueryRef && (
    <PirFiltersDisplayComponent
      {...props}
      queryRef={filtersRepresentativesQueryRef}
    />
  );
};

export default PirFiltersDisplay;
