import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import { Tooltip } from '@mui/material';
import { InformationOutline } from 'mdi-material-ui';
import { filterValue, SELF_ID_VALUE } from '../utils/filters/filtersUtils';
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
  filterDefinition?: FilterDefinition;
  filterOperator?: string;
}

const FilterValuesContent: FunctionComponent<
FilterValuesContentProps
> = ({ redirection, isFilterTooltip, filterKey, id, value, filterDefinition, filterOperator }) => {
  const { t_i18n } = useFormatter();
  const { stixCoreObjectTypes } = useAttributes();
  const completedStixCoreObjectTypes = stixCoreObjectTypes.concat(['Stix-Core-Object', 'Stix-Cyber-Observable']);

  const filterType = filterDefinition?.type;
  let displayedValue = isFilterTooltip
    ? filterValue(filterKey, value, filterType, filterOperator)
    : truncate(filterValue(filterKey, value, filterType, filterOperator), 15);
  if (displayedValue === null) {
    return (
      <>
        <del>{t_i18n('deleted')}</del>
      </>
    );
  }
  if (displayedValue === SELF_ID_VALUE) {
    displayedValue = <div>
      <span>
        {displayedValue}
      </span>
      <Tooltip
        style={{ marginLeft: 3, marginTop: -5, paddingTop: 7 }}
        title={t_i18n('Current entity refers to the entity in which you will use the Fintel template. Removing this filter means you will lost the context of the container in which the template is used.')}
      >
        <InformationOutline color="primary"/>
      </Tooltip>
    </div>;
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
