import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { FilterListOutlined } from '@mui/icons-material';
import Popover from '@mui/material/Popover';
import Tooltip from '@mui/material/Tooltip';
import { RayEndArrow, RayStartArrow } from 'mdi-material-ui';
import React, { ReactElement } from 'react';
import { useFormatter } from '../../../../components/i18n';

interface ListFiltersWithoutLocalStorageProps {
  handleOpenFilters: (event: React.SyntheticEvent) => void;
  handleCloseFilters: () => void;
  open: boolean;
  anchorEl: Element | null;
  filterElement: ReactElement;
  variant?: string;
  type?: string;
}

const ListFiltersWithoutLocalStorage = ({
  handleOpenFilters,
  handleCloseFilters,
  open,
  anchorEl,
  filterElement,
  variant,
  type,
}: ListFiltersWithoutLocalStorageProps) => {
  const { t_i18n } = useFormatter();
  let icon = <FilterListOutlined fontSize="medium" />;
  let tooltip = t_i18n('Filters');
  if (type === 'from') {
    icon = <RayStartArrow fontSize="medium" />;
    tooltip = t_i18n('Dynamic source filters');
  } else if (type === 'to') {
    icon = <RayEndArrow fontSize="medium" />;
    tooltip = t_i18n('Dynamic target filters');
  }
  return (
    <div
      style={{
        float: 'left',
        margin: '-3px 0 0 -5px',
      }}
    >
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
        sx={{
          '& .MuiPaper-root': {
            width: 600,
            padding: 20,
          },
        }}
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
