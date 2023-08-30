import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import { entityFilters, filterValue } from '../utils/filters/filtersUtils';
import { truncate } from '../utils/String';
import { useFormatter } from './i18n';

export const filterIconButtonContentQuery = graphql`
    query FilterIconButtonContentQuery(
        $filters: FilterGroup!
    ) {
        filtersRepresentatives(filters: $filters) {
            mode
            filters {
                key
                values
                operator
                mode
                representatives {
                    id
                    value
                }
            }
        }
    }
`;
interface FilterIconButtonContentProps {
  redirection?: boolean;
  filterKey: string;
  id: string | null;
  value?: string | null;
}

const FilterIconButtonContent: FunctionComponent<FilterIconButtonContentProps> = ({
  redirection,
  filterKey,
  id,
  value,
}) => {
  const { t } = useFormatter();

  const displayedValue = truncate(filterValue(filterKey, id, value), 15);

  if (displayedValue === null) {
    return (
      <>
        <del>{t('deleted')}</del>
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
  return (
    <span>{displayedValue}</span>
  );
};

export default FilterIconButtonContent;
