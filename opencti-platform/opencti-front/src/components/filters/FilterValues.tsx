import React, { Fragment, FunctionComponent } from 'react';
import { last } from 'ramda';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { WarningOutlined } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import { useFormatter } from '../i18n';
import { FiltersRestrictions, isFilterEditable, isFilterGroupNotEmpty, isRegardingOfFilterWarning, useFilterDefinition } from '../../utils/filters/filtersUtils';
import { isDateIntervalTranslatable, translateDateInterval, truncate } from '../../utils/String';
import FilterValuesContent from '../FilterValuesContent';
import { FilterRepresentative } from './FiltersModel';
import { Filter } from '../../utils/filters/filtersHelpers-types';
import useSchema from '../../utils/hooks/useSchema';
import FilterValuesForDynamicSubKey from './FilterValuesForDynamicSubKey';
import { useTheme } from '@mui/material/styles';
import { Stack } from '@mui/material';
import type { WidgetHost } from '../../utils/widget/widget';
import Button from '@common/button/Button';

interface FilterValuesProps {
  label: string | React.JSX.Element;
  tooltip?: boolean;
  currentFilter: Filter;
  parentFilter?: Filter;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  redirection?: boolean;
  handleSwitchLocalMode?: (filter: Filter) => void;
  onClickLabel?: (event: React.MouseEvent<HTMLButtonElement>) => void;
  isReadWriteFilter?: boolean;
  chipColor?: ChipOwnProps['color'];
  noLabelDisplay?: boolean;
  entityTypes?: string[];
  filtersRestrictions?: FiltersRestrictions;
  host?: WidgetHost;
}

const FilterValues: FunctionComponent<FilterValuesProps> = ({
  label,
  tooltip,
  parentFilter,
  currentFilter,
  filtersRepresentativesMap,
  redirection,
  handleSwitchLocalMode,
  onClickLabel,
  isReadWriteFilter,
  chipColor,
  noLabelDisplay,
  entityTypes,
  filtersRestrictions,
  host,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { schema: { scos } } = useSchema();

  const filterKey = currentFilter.key;
  const filterOperator = currentFilter.operator;
  const filterValues = currentFilter.values;
  const isOperatorNil = ['nil', 'not_nil'].includes(filterOperator ?? 'eq');
  const isOperatorChange = ['has_changed', 'not_has_changed'].includes(filterOperator ?? 'eq');
  const deactivatePopoverMenu = !isFilterEditable(filtersRestrictions, filterKey, filterValues) || !isReadWriteFilter;
  const onCLick = deactivatePopoverMenu ? () => { } : onClickLabel;

  const buttonStyles = {
    background: 'none',
    border: 'none',
    padding: 0,
    font: 'inherit',
    color: 'inherit',
    backgroundColor: 'inherit !important',
    ...(!deactivatePopoverMenu && {
      cursor: 'pointer',
      '&:hover': {
        textDecorationLine: 'underline',
      },
    })
  }

  // special case for nil/not_nil
  if (isOperatorNil) {
    return (
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Button
          type="button"
          sx={buttonStyles}
          onClick={onCLick}
        >
          <strong>
            {label}
          </strong>
        </Button>{' '}
        <span>
          {filterOperator === 'nil' ? t_i18n('is empty') : t_i18n('is not empty')}
        </span>
      </div>
    );
  }

  // special case for has_changed/not_has_changed
  if (isOperatorChange) {
    return (
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Button
          type="button"
          sx={buttonStyles}
          onClick={onCLick}
        >
          <strong>
            {label}
          </strong>
        </Button>{' '}
        <span>
          {filterOperator === 'has_changed' ? t_i18n('has changed') : t_i18n('has not changed')}
        </span>
      </div>
    );
  }

  // special case for within operator in a 'last XX' format (ie : value1 is a relative date before now, and value2 is 'now')
  if (filterOperator === 'within'
    && isDateIntervalTranslatable(filterValues)
  ) {
    const relativeValue = translateDateInterval(filterValues, t_i18n);
    return (
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Button
          type="button"
          sx={buttonStyles}
          onClick={onCLick}
        >
          <strong>
            {label}
          </strong>
        </Button>{' '}
        <span>
          {relativeValue}
        </span>
      </div>
    );
  }

  // general cases
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);
  const values = filterValues.map((id) => {
    const isLocalModeSwitchable = isReadWriteFilter
      && handleSwitchLocalMode
      && !filtersRestrictions?.preventLocalModeSwitchingFor?.includes(filterKey)
      && isFilterEditable(filtersRestrictions, filterKey, filterValues);
    const localModeStyle = isLocalModeSwitchable
      ? {
        background: 'none',
        color: 'inherit',
        display: 'inline-block',
        height: '100%',
        borderRadius: 0,
        margin: '0 5px 0 5px',
        padding: '0 5px 0 5px',
        cursor: 'pointer',
        backgroundColor: theme.palette.action?.disabled,
        fontFamily: 'Consolas, monaco, monospace',
        '&:hover': {
          textDecorationLine: 'underline',
          backgroundColor: theme.palette.text?.disabled,
        },
      }
      : {
        background: 'none',
        color: 'inherit',
        display: 'inline-block',
        height: '100%',
        borderRadius: 0,
        margin: '0 5px 0 5px',
        padding: '0 5px 0 5px',
        backgroundColor: theme.palette.action?.disabled,
        fontFamily: 'Consolas, monaco, monospace',
      };
    const operatorOnClick = isLocalModeSwitchable ? () => handleSwitchLocalMode(currentFilter) : undefined;
    const value = filtersRepresentativesMap.get(id) ? filtersRepresentativesMap.get(id)?.value : id;
    const isRegardingOfFilter = parentFilter?.key === 'regardingOf' || parentFilter?.key === 'dynamicRegardingOf';
    return (
      <Fragment key={id}>
        {filterOperator === 'within'
          ? (
            <>
              {filterValues[0] === id && <span>[</span>}
              <FilterValuesContent
                isFilterTooltip={!!tooltip}
                filterKey={filterKey}
                id={id}
                value={value}
                filterDefinition={filterDefinition}
                filterOperator={filterOperator}
                host={host}
              />
              <span>
                {last(filterValues) === id ? ']' : ', '}
              </span>
            </>
          )
          : (
            <>
              <FilterValuesContent
                redirection={tooltip ? false : redirection}
                isFilterTooltip={!!tooltip}
                filterKey={filterKey}
                id={id}
                value={value}
                filterDefinition={filterDefinition}
                filterOperator={filterOperator}
                host={host}
              />
              {last(filterValues) !== id && isRegardingOfFilter
                && (
                  <button
                    type="button"
                    style={{
                      background: 'none',
                      border: 'none',
                      padding: 0,
                      color: 'inherit',
                      display: 'inline-block',
                      height: '100%',
                      borderRadius: 0,
                      margin: '0 2px 0 0',
                      fontFamily: 'Consolas, monaco, monospace',
                    }}
                    onClick={operatorOnClick}
                  >
                    ,
                  </button>
                )
              }
              {last(filterValues) !== id && !isRegardingOfFilter
                && (
                  <button type="button" style={localModeStyle} onClick={operatorOnClick}>
                    {t_i18n((currentFilter.mode ?? 'or').toUpperCase())}
                  </button>
                )
              }
            </>
          )
        }
      </Fragment>
    );
  });

  if (filterKey === 'regardingOf' || filterKey === 'dynamicRegardingOf') {
    const sortedFilterValues = [...filterValues].sort((a, b) => -a.key.localeCompare(b.key)); // display type first, then id

    // add warning for (relationship type / ids) combinations that may not display all the results because of denormalization
    const isWarning = isRegardingOfFilterWarning(currentFilter, scos.map((n) => n.id), filtersRepresentativesMap);

    return (
      <Stack direction="row" sx={{ alignItems: 'center' }}>
        {isWarning && (
          <Tooltip title={
            t_i18n('', {
              id: 'All the results may not be displayed for these filter values, read documentation for more information.',
              values: {
                link: (
                  <Link target="_blank" to="https://docs.opencti.io/latest/reference/filters/?h=regarding#the-regardingof-filter-key">
                    {t_i18n('read documentation')}
                  </Link>
                ),
              },
            })
          }
          >
            <WarningOutlined
              color="inherit"
              style={{ fontSize: 20, color: theme.palette.error.main, marginRight: 4 }}
            />
          </Tooltip>
        )}
        <Button
          type="button"
          sx={buttonStyles}
          onClick={onCLick}
        >
          <strong>
            {label}
          </strong>
        </Button>{' '}
        <Box sx={{ display: 'flex', flexDirection: 'row', overflow: 'hidden' }}>
          {sortedFilterValues
            .map((val) => {
              const subKey = val.key;
              const keyLabel = (
                <>
                  {truncate(t_i18n(subKey), 20)}
                  <>&nbsp;=</>
                </>
              );
              if (subKey === 'dynamic') {
                const [dynamicValue] = val.values;
                if (!isFilterGroupNotEmpty(dynamicValue)) {
                  return <div key={val.key} />;
                }
                return (
                  <FilterValuesForDynamicSubKey
                    key={val.key}
                    filterValue={dynamicValue}
                    chipColor={chipColor}
                  />
                );
              }
              return (
                <Fragment key={val.key}>
                  <Tooltip
                    title={(
                      <FilterValues
                        label={keyLabel}
                        tooltip={true}
                        parentFilter={currentFilter}
                        currentFilter={val}
                        filtersRepresentativesMap={filtersRepresentativesMap}
                        host={host}
                      />
                    )}
                  >
                    <Box
                      sx={{
                        px: 0.5,
                      }}
                    >
                      <FilterValues
                        label={keyLabel}
                        tooltip={false}
                        parentFilter={currentFilter}
                        currentFilter={val}
                        filtersRepresentativesMap={filtersRepresentativesMap}
                        redirection
                        noLabelDisplay={true}
                        host={host}
                      />
                    </Box>
                  </Tooltip>
                </Fragment>
              );
            })
          }
        </Box>
      </Stack>
    );
  }
  if (noLabelDisplay) {
    return (
      <>{values}</>
    );
  }
  if (filterKey === 'dynamicFrom' || filterKey === 'dynamicTo') {
    return (
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Button
          type="button"
          sx={buttonStyles}
          onClick={onCLick}
        >
          <strong>
            {label}
          </strong>
        </Button>{' '}
        <Chip
          label={t_i18n('Dynamic filter')}
          color={chipColor}
        />
      </div>
    );
  }
  return (
    <div style={{ display: 'flex', alignItems: 'center' }}>
      <Button
        type="button"
        sx={buttonStyles}
        onClick={onCLick}
      >
        <strong>
          {label}
        </strong>
      </Button>{' '}
      {values}
    </div>
  );
};

export default FilterValues;
