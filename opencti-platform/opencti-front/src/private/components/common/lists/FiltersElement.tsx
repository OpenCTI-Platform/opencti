import Grid from '@mui/material/Grid';
import TextField from '@mui/material/TextField';
import React, { Dispatch, FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import {
  directFilters,
  FiltersVariant,
} from '../../../../utils/filters/filtersUtils';
import FilterDate from './FilterDate';
import FilterAutocomplete from './FilterAutocomplete';
import { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  helpertext: {
    display: 'inline-block',
    color: theme.palette.text?.secondary,
    marginTop: 20,
  },
}));

interface FiltersElementProps {
  variant?: string;
  keyword: string;
  availableFilterKeys: string[];
  handleChangeKeyword: (event: React.SyntheticEvent) => void;
  noDirectFilters?: boolean;
  setInputValues: Dispatch<Record<string, string | Date>>;
  inputValues: Record<string, string | Date>;
  defaultHandleAddFilter: (
    k: string,
    id: string,
    value: Record<string, unknown> | string,
    event?: React.SyntheticEvent
  ) => void;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  allEntityTypes?: boolean;
}

const FiltersElement: FunctionComponent<FiltersElementProps> = ({
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
  const classes = useStyles();
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
        {availableFilterKeys
          .filter((n) => noDirectFilters || !directFilters.includes(n))
          .map((filterKey) => {
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

export default FiltersElement;
