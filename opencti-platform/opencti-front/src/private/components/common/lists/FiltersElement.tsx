import Grid from '@mui/material/Grid';
import TextField from '@mui/material/TextField';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { useBuildFilterKeysMapFromEntityType, FiltersVariant } from '../../../../utils/filters/filtersUtils';
import FilterDate from './FilterDate';
import FilterAutocomplete from './FilterAutocomplete';
import type { Theme } from '../../../../components/Theme';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  helpertext: {
    display: 'inline-block',
    color: theme.palette.text?.secondary,
    marginTop: 20,
  },
}));

export type FilterElementsInputValue = {
  key: string;
  values: string[];
  operator?: string;
};

export interface FiltersElementProps {
  variant?: string;
  keyword: string;
  availableFilterKeys: string[];
  searchContext: {
    entityTypes: string[];
    elementId?: string[];
  };
  handleChangeKeyword: (event: React.ChangeEvent) => void;
  setInputValues: (
    value: {
      key: string;
      values: string[];
      operator?: string;
    }[],
  ) => void;
  inputValues: {
    key: string;
    values: string[];
    operator?: string;
  }[];
  defaultHandleAddFilter: HandleAddFilter;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  disabled?: boolean;
}

const FiltersElement: FunctionComponent<FiltersElementProps> = ({
  variant,
  keyword,
  availableFilterKeys,
  searchContext,
  handleChangeKeyword,
  setInputValues,
  inputValues,
  defaultHandleAddFilter,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  disabled = false,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const { entityTypes } = searchContext;
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);
  const displayedFilters = availableFilterKeys
    .map((key) => {
      if (filterKeysMap.get(key)?.type === 'date') {
        if (key === 'valid_until') {
          return [{ key, operator: 'lt' }];
        }
        if (key === 'valid_from') {
          return [{ key, operator: 'gt' }];
        }
        return [
          { key, operator: 'gt' },
          { key, operator: 'lt' },
        ];
      }
      return { key, operator: undefined };
    })
    .flat();
  return (
    <>
      <Grid container={true} spacing={2}>
        {variant === FiltersVariant.dialog && (
          <Grid item xs={12}>
            <TextField
              label={t_i18n('Global keyword')}
              variant="outlined"
              size="small"
              fullWidth={true}
              value={keyword}
              onChange={handleChangeKeyword}
              disabled={disabled}
            />
          </Grid>
        )}
        {displayedFilters.map((filter, index) => {
          const filterKey = filter.key;
          const isDateFilter = filterKeysMap.get(filterKey)?.type === 'date';
          const filterLabel = t_i18n(filterKeysMap.get(filterKey)?.label ?? filterKey);
          if (isDateFilter) {
            return (
              <Grid
                key={`${filterKey}_${index}`}
                item
                xs={6}
              >
                <FilterDate
                  defaultHandleAddFilter={defaultHandleAddFilter}
                  filterKey={filterKey}
                  inputValues={inputValues}
                  setInputValues={setInputValues}
                  filterLabel={filterLabel}
                />
              </Grid>);
          }
          return (
            <Grid key={filterKey} item xs={6}>
              <FilterAutocomplete
                filterKey={filterKey}
                searchContext={searchContext}
                defaultHandleAddFilter={defaultHandleAddFilter}
                inputValues={inputValues}
                setInputValues={setInputValues}
                availableEntityTypes={availableEntityTypes}
                availableRelationshipTypes={availableRelationshipTypes}
                availableRelationFilterTypes={availableRelationFilterTypes}
                openOnFocus={true}
                filterLabel={filterLabel}
                disabled={disabled}
              />
            </Grid>
          );
        })}
      </Grid>
      <div className={classes.helpertext}>
        {t_i18n('Use Alt + click to exclude items')}
      </div>
    </>
  );
};

export default FiltersElement;
