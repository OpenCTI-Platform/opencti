import Grid from '@mui/material/Grid';
import TextField from '@mui/material/TextField';
import { compose } from 'ramda';
import React from 'react';
import withStyles from '@mui/styles/withStyles';
import { useFormatter } from '../../../../components/i18n';
import { directFilters, FiltersVariant } from '../../../../utils/filters/filtersUtils';
import FilterDate from './FilterDate';
import FilterAutocomplete from './FilterAutocomplete';

const styles = (theme) => ({
  helpertext: {
    display: 'inline-block',
    color: theme.palette.text.secondary,
    marginTop: 20,
  },
});

const FiltersElement = ({
  classes,
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
        {availableFilterKeys.filter(
          (n) => noDirectFilters || !directFilters.includes(n),
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
              />
            </Grid>
          );
        })}
      </Grid>
      <div className={classes.helpertext}>
        {t('Use')} <code>alt</code> + <code>click</code> {t('to exclude items')}
        .
      </div>
    </div>
  );
};

export default compose(withStyles(styles))(FiltersElement);
