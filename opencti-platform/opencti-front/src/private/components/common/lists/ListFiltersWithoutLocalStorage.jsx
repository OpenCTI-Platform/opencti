import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { FilterListOutlined } from '@mui/icons-material';
import Popover from '@mui/material/Popover';
import Tooltip from '@mui/material/Tooltip';
import { RayEndArrow, RayStartArrow } from 'mdi-material-ui';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  filters: {
    float: 'left',
    margin: '-3px 0 0 -5px',
  },
  container: {
    width: 600,
    padding: 20,
  },
}));

const ListFiltersWithoutLocalStorage = ({
  handleOpenFilters,
  handleCloseFilters,
  open,
  anchorEl,
  filterElement,
  variant,
  type,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  let icon = <FilterListOutlined fontSize="medium" />;
  let tooltip = t_i18n('Filters');
  // let color = 'primary';
  if (type === 'from') {
    icon = <RayStartArrow fontSize="medium" />;
    tooltip = t_i18n('Dynamic source filters');
    // color = 'warning';
  } else if (type === 'to') {
    icon = <RayEndArrow fontSize="medium" />;
    tooltip = t_i18n('Dynamic target filters');
    // color = 'success';
  }
  return (
    <div className={classes.filters}>
      {variant === 'text' ? (
        <Tooltip title={tooltip}>
          <Button
            onClick={handleOpenFilters}
            startIcon={icon}
            size="small"
            style={{ float: 'left', margin: '0 15px 0 7px' }}
          >
            {t_i18n('Filters')}
          </Button>
        </Tooltip>
      ) : (
        <Tooltip title={tooltip}>
          <IconButton
            onClick={handleOpenFilters}
            style={{ float: 'left', marginTop: -2 }}
          >
            {icon}
          </IconButton>
        </Tooltip>
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
      <div className="clearfix" />
    </div>
  );
};

export default ListFiltersWithoutLocalStorage;
