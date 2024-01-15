import Button from '@mui/material/Button';
import { FilterListOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Popover from '@mui/material/Popover';
import Tooltip from '@mui/material/Tooltip';
import { RayEndArrow, RayStartArrow } from 'mdi-material-ui';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';

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
  size,
  fontSize,
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
  let icon = <FilterListOutlined fontSize={fontSize || 'medium'} />;
  let tooltip = t_i18n('Filters');
  let color = 'primary';
  if (type === 'from') {
    icon = <RayStartArrow fontSize={fontSize || 'medium'} />;
    tooltip = t_i18n('Dynamic source filters');
    color = 'warning';
  } else if (type === 'to') {
    icon = <RayEndArrow fontSize={fontSize || 'medium'} />;
    tooltip = t_i18n('Dynamic target filters');
    color = 'success';
  }
  return (
    <div className={classes.filters}>
      {variant === 'text' ? (
        <Tooltip title={tooltip}>
          <Button
            variant="contained"
            color={color}
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
            color={color}
            onClick={handleOpenFilters}
            style={{ float: 'left', marginTop: -2 }}
            size={size || 'large'}
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
