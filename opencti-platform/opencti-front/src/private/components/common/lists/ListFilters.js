import Button from '@mui/material/Button';
import { FilterListOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Popover from '@mui/material/Popover';
import * as R from 'ramda';
import Autocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { directFilters } from '../../../../utils/filters/filtersUtils';

const useStyles = makeStyles((theme) => ({
  filters: {
    float: 'left',
    margin: '-3px 0 0 -5px',
  },
  container: {
    width: 490,
    padding: 20,
  },
  autocomplete: {
    float: 'left',
    margin: '5px 10px 0 10px',
    width: 200,
  },
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

const ListFilters = ({
  size,
  fontSize,
  handleOpenFilters,
  handleCloseFilters,
  open,
  anchorEl,
  noDirectFilters,
  availableFilterKeys,
  searchScope,
  entities,
  inputValues,
  renderSearchScopeSelection,
  filterElement,
  variant,
  searchEntities,
  handleChange,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  return (
    <div className={classes.filters}>
      {variant === 'text' ? (
        <Button
          variant="contained"
          color="primary"
          onClick={handleOpenFilters}
          startIcon={<FilterListOutlined />}
          size="small"
          style={{ float: 'left', margin: '0 15px 0 7px' }}
        >
          {t('Filters')}
        </Button>
      ) : (
        <IconButton
          color="primary"
          onClick={handleOpenFilters}
          style={{ float: 'left', marginTop: -2 }}
          size={size || 'large'}
        >
          <FilterListOutlined fontSize={fontSize || 'medium'} />
        </IconButton>
      )}
      <Popover
        classes={{ paper: classes.container }}
        open={open}
        anchorEl={anchorEl}
        onClose={handleCloseFilters}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'center',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'center',
        }}
        elevation={1}
      >
        {filterElement}
      </Popover>
      {!noDirectFilters
        && R.filter(
          (n) => R.includes(n, directFilters),
          availableFilterKeys,
        ).map((filterKey) => {
          let options = [];
          if (['fromId', 'toId'].includes(filterKey)) {
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
            <Autocomplete
              key={filterKey}
              className={classes.autocomplete}
              selectOnFocus={true}
              autoSelect={false}
              autoHighlight={true}
              options={options}
              getOptionLabel={(option) => (option.label ? option.label : '')}
              noOptionsText={t('No available options')}
              onInputChange={(event) => searchEntities(filterKey, event)}
              onChange={(event, value) => handleChange(filterKey, event, value)}
              isOptionEqualToValue={(option, value) => option.value === value}
              inputValue={inputValues[filterKey] || ''}
              groupBy={
                ['fromId', 'toId'].includes(filterKey)
                  ? (option) => option.type
                  : null
              }
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
                    endAdornment: ['fromId', 'toId'].includes(filterKey)
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
          );
        })}
      <div className="clearfix" />
    </div>
  );
};

export default ListFilters;
