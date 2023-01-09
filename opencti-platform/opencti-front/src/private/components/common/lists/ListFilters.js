import Button from '@mui/material/Button';
import { FilterListOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Popover from '@mui/material/Popover';
import * as R from 'ramda';
import { RayStartArrow, RayEndArrow } from 'mdi-material-ui';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { directFilters } from '../../../../utils/filters/filtersUtils';
import FilterAutocomplete from './FilterAutocomplete';

const useStyles = makeStyles(() => ({
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
  filterElement,
  variant,
  type,
  inputValues,
  setInputValues,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  allEntityTypes,
  defaultHandleAddFilter,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  let icon = <FilterListOutlined fontSize={fontSize || 'medium'} />;
  if (type === 'from') {
    icon = <RayStartArrow fontSize={fontSize || 'medium'} />;
  } else if (type === 'to') {
    icon = <RayEndArrow fontSize={fontSize || 'medium'} />;
  }
  return (
    <div className={classes.filters}>
      {variant === 'text' ? (
        <Button
          variant="contained"
          color="primary"
          onClick={handleOpenFilters}
          startIcon={icon}
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
          {icon}
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
        className="noDrag"
      >
        {filterElement}
      </Popover>
      {!noDirectFilters
        && R.filter((n) => R.includes(n, directFilters), availableFilterKeys).map(
          (filterKey) => {
            return (
              <div className={classes.autocomplete} key={filterKey}>
                <FilterAutocomplete
                  filterKey={filterKey}
                  defaultHandleAddFilter={defaultHandleAddFilter}
                  inputValues={inputValues}
                  setInputValues={setInputValues}
                  availableEntityTypes={availableEntityTypes}
                  availableRelationshipTypes={availableRelationshipTypes}
                  availableRelationFilterTypes={availableRelationFilterTypes}
                  allEntityTypes={allEntityTypes}
                  openOnFocus={false}
                />
              </div>
            );
          },
        )}
      <div className="clearfix" />
    </div>
  );
};

export default ListFilters;
