import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import { entityFilters, filterValue } from '../utils/filters/filtersUtils';
import { truncate } from '../utils/String';
import { useFormatter } from './i18n';

export const filterValuesContentQuery = graphql`
    query FilterValuesContentQuery($filters: FilterGroup!) {
        filtersRepresentatives(filters: $filters) {
            id
            value
            entity_type
            color
        }
    }
`;
interface FilterValuesContentProps {
  redirection?: boolean;
  isFilterTooltip?: boolean;
  filterKey: string;
  id: string | null;
  value?: string | null;
}

const FilterValuesContent: FunctionComponent<
FilterValuesContentProps
> = ({ redirection, isFilterTooltip, filterKey, id, value }) => {
  const { t_i18n } = useFormatter();
  const displayedValue = isFilterTooltip
    ? filterValue(filterKey, value)
    : truncate(filterValue(filterKey, value), 15);
  if (displayedValue === null) {
    return (
      <>
        <del>{t_i18n('deleted')}</del>
      </>
    );
  }
  if (redirection && entityFilters.includes(filterKey)) {
    return (
      <Link to={`/dashboard/id/${id}`}>
        <span color="primary">{displayedValue}</span>
      </Link>
    );
  }
  return <span>{displayedValue}</span>;
};

export default FilterValuesContent;
