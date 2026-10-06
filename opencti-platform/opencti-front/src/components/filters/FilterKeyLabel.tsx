import Box from '@mui/material/Box';
import { FunctionComponent } from 'react';
import { Filter } from '../../utils/filters/filtersHelpers-types';
import { convertOperatorToIcon, filterOperatorsWithIcon, getFilterDefinitionFromFilterKeysMap } from '../../utils/filters/filtersUtils';
import { truncate } from '../../utils/String';
import { FilterDefinition } from '../../utils/hooks/useAuth';
import { useFormatter } from '../i18n';

interface FilterKeyLabelProps {
  filter: Filter;
  filterKeysMap: Map<string, FilterDefinition>;
}

/** Label of a filter chip: the translated key followed by its operator (icon, or text + colon). */
const FilterKeyLabel: FunctionComponent<FilterKeyLabelProps> = ({ filter, filterKeysMap }) => {
  const { t_i18n } = useFormatter();
  const filterLabel = t_i18n(getFilterDefinitionFromFilterKeysMap(filter.key, filterKeysMap)?.label ?? filter.key);
  const filterOperator = filter.operator ?? 'eq';
  const isOperatorDisplayed = filterOperatorsWithIcon.includes(filterOperator);
  return (
    <>
      {truncate(filterLabel, 20)}
      {!isOperatorDisplayed && (
        <Box
          component="span"
          sx={{ padding: '0 4px', fontWeight: 'normal' }}
        >
          {t_i18n(filterOperator)}
        </Box>
      )}
      {isOperatorDisplayed
        ? convertOperatorToIcon(filterOperator)
        : filter.values.length > 0 && ':'}
    </>
  );
};

export default FilterKeyLabel;
