import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import { filterValue } from '../utils/filters/filtersUtils';
import { truncate } from '../utils/String';
import { useFormatter } from './i18n';
import { FilterDefinition } from '../utils/hooks/useAuth';
import useAttributes from '../utils/hooks/useAttributes';

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
  filterDefinition?: FilterDefinition
}

const FilterValuesContent: FunctionComponent<
FilterValuesContentProps
> = ({ redirection, isFilterTooltip, filterKey, id, value, filterDefinition }) => {
  const { t_i18n } = useFormatter();
  const { stixCoreObjectTypes } = useAttributes();
  const completedStixCoreObjectTypes = stixCoreObjectTypes.concat(['Stix-Core-Object', 'Stix-Cyber-Observable']);

  const filterType = filterDefinition?.type;
  const displayedValue = isFilterTooltip
    ? filterValue(filterKey, value, filterType)
    : truncate(filterValue(filterKey, value, filterType), 15);
  if (displayedValue === null) {
    return (
      <>
        <del>{t_i18n('deleted')}</del>
      </>
    );
  }
  const isRedirectableFilter = filterDefinition
    && filterType === 'id'
    && filterDefinition.elementsForFilterValuesSearch
    && filterDefinition.elementsForFilterValuesSearch.every((idType) => completedStixCoreObjectTypes.includes(idType));
  if (redirection && isRedirectableFilter) {
    return (
      <Link to={`/dashboard/id/${id}`}>
        <span color="primary">{displayedValue}</span>
      </Link>
    );
  }
  return <span>{displayedValue}</span>;
};

export default FilterValuesContent;
