import Grid from '@mui/material/Grid';
import TextField from '@mui/material/TextField';
import * as R from 'ramda';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import Autocomplete from '@mui/material/Autocomplete';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { directFilters, FiltersVariant } from '../../../../utils/filters/filtersUtils';

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
}));

const FiltersElement = ({
  variant,
  keyword,
  availableFilterKeys,
  handleChangeKeyword,
  handleChangeDate,
  handleAcceptDate,
  handleValidateDate,
  noDirectFilters,
  inputValues,
  searchScope,
  entities,
  handleChange,
  searchEntities,
  renderSearchScopeSelection,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  return (
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
              <DatePicker
                label={t(`filter_${filterKey}`)}
                value={inputValues[filterKey] || null}
                variant="inline"
                disableToolbar={false}
                autoOk={true}
                allowKeyboardControl={true}
                onChange={(value) => handleChangeDate(filterKey, value)}
                onAccept={(value) => handleAcceptDate(filterKey, value)}
                renderInput={(params) => (
                  <TextField
                    variant="outlined"
                    size="small"
                    fullWidth={variant === 'dialog'}
                    onKeyDown={(event) => handleValidateDate(filterKey, event)}
                    {...params}
                  />
                )}
              />
            </Grid>
          );
        }
        let options = [];
        if (['fromId', 'toId', 'objectContains'].includes(filterKey)) {
          if (searchScope[filterKey] && searchScope[filterKey].length > 0) {
            options = (entities[filterKey] || [])
              .filter((n) => (searchScope[filterKey] || []).includes(n.type))
              .sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
          } else {
            // eslint-disable-next-line max-len
            options = (entities[filterKey] || []).sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
          }
        } else if (entities[filterKey]) {
          options = entities[filterKey];
        }
        return (
          <Grid key={filterKey} item={true} xs={6}>
            <Autocomplete
              selectOnFocus={true}
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
                ['fromId', 'toId', 'objectContains'].includes(filterKey)
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
                    endAdornment: ['fromId', 'toId', 'objectContains'].includes(filterKey)
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
  );
};

export default FiltersElement;
