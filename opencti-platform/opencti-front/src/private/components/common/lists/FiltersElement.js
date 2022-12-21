import Grid from '@mui/material/Grid';
import TextField from '@mui/material/TextField';
import * as R from 'ramda';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import {
  directFilters,
  FiltersVariant,
} from '../../../../utils/filters/filtersUtils';

const useStyles = makeStyles((theme) => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  helpertext: {
    display: 'inline-block',
    marginTop: 20,
    color: theme.palette.primary.main,
    size: '10px',
  },
}));
import FilterDate from './FilterDate';
import FilterAutocomplete from './FilterAutocomplete';

const FiltersElement = ({
  variant,
  keyword,
  availableFilterKeys,
  handleChangeKeyword,
  noDirectFilters,
  setInputValues,
  inputValues,
  defaultHandleAddFilter,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  allEntityTypes,
}) => {
  const { t } = useFormatter();

  return (
    <div>
    <Grid container={true} spacing={2}>
      {variant === FiltersVariant.dialog && (
        <Grid item={true} xs={12}>
          <TextField
            label={t('Global keyword')}
            variant="outlined"
            size="small"
            fullWidth={true}
            value={keyword}
            onChange={handleChangeKeyword}
          />
        </Grid>
      )}
      {R.filter(
        (n) => noDirectFilters || !R.includes(n, directFilters),
        availableFilterKeys,
      ).map((filterKey) => {
        if (
          filterKey.endsWith('start_date')
          || filterKey.endsWith('end_date')
        ) {
          return (
            <Grid key={filterKey} item={true} xs={6}>
              <FilterDate
                defaultHandleAddFilter={defaultHandleAddFilter}
                filterKey={filterKey}
                inputValues={inputValues}
                setInputValues={setInputValues}
                variant={variant}
              />
            </Grid>
          );
        }

        return (
          <Grid key={filterKey} item={true} xs={6}>
            <FilterAutocomplete
              filterKey={filterKey}
              defaultHandleAddFilter={defaultHandleAddFilter}
              inputValues={inputValues}
              setInputValues={setInputValues}
              availableEntityTypes={availableEntityTypes}
              availableRelationshipTypes={availableRelationshipTypes}
              availableRelationFilterTypes={availableRelationFilterTypes}
              allEntityTypes={allEntityTypes}
              openOnFocus={true}
              autoSelect={false}
              autoHighlight={true}
              getOptionLabel={(option) => (option.label ? option.label : '')}
              noOptionsText={t('No available options')}
              options={options}
              onInputChange={(event) => searchEntities(filterKey, event)}
              inputValue={inputValues[filterKey] || ''}
              onChange={(event, value) => handleChange(filterKey, event, value)}
              groupBy={
                ['elementId', 'fromId', 'toId', 'objectContains'].includes(filterKey)
                  ? (option) => option.type
                  : (option) => t(option.group ? option.group : `filter_${filterKey}`)
              }
              isOptionEqualToValue={(option, value) => option.value === value.value}
              renderInput={(params) => (
                <TextField
                  {...R.dissoc('InputProps', params)}
                  label={t(`filter_${filterKey}`)}
                  variant="outlined"
                  size="small"
                  fullWidth={true}
                  onFocus={(event) => searchEntities(filterKey, event)}
                  InputProps={{
                    ...params.InputProps,
                    endAdornment: ['elementId', 'fromId', 'toId', 'objectContains'].includes(filterKey)
                      ? renderSearchScopeSelection(filterKey)
                      : params.InputProps.endAdornment,
                  }}
                />
              )}
              renderOption={(props, option) => (
                <li {...props}>
                  <div
                    className={classes.icon}
                    style={{ color: option.color }}
                  >
                    <ItemIcon type={option.type} />
                  </div>
                  <div className={classes.text}>{option.label}</div>
                </li>
              )}
            />
          </Grid>
        );
      })}
    </Grid>
      <div className={classes.helpertext}>{t('Use Alt + click to exclude items')}</div>
    </div>
  );
};

export default FiltersElement;
