import React from 'react';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { BiotechOutlined } from '@mui/icons-material';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { useFormatter } from '../../../../components/i18n';
import FilterIconButton from '../../../../components/FilterIconButton';

const DialogFilters = ({
  handleOpenFilters,
  disabled,
  size,
  fontSize,
  open,
  filters,
  handleCloseFilters,
  defaultHandleRemoveFilter,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  handleSearch,
  filterElement,
  searchContext,
  availableEntityTypes,
  availableRelationshipTypes,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <React.Fragment>
      <Tooltip title={t_i18n('Advanced search')}>
        <IconButton
          onClick={handleOpenFilters}
          disabled={disabled}
          size={size || 'medium'}
        >
          <BiotechOutlined fontSize={fontSize || 'medium'} />
        </IconButton>
      </Tooltip>
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={open}
        onClose={handleCloseFilters}
        fullWidth={true}
        maxWidth="md"
      >
        <DialogTitle>{t_i18n('Advanced search')}</DialogTitle>
        <DialogContent style={{ paddingTop: 10 }}>
          <FilterIconButton
            filters={filters}
            handleRemoveFilter={defaultHandleRemoveFilter}
            handleSwitchGlobalMode={handleSwitchGlobalMode}
            handleSwitchLocalMode={handleSwitchLocalMode}
            styleNumber={2}
            searchContext={searchContext}
            availableEntityTypes={availableEntityTypes}
            availableRelationshipTypes={availableRelationshipTypes}
          />
          {filterElement}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseFilters}>{t_i18n('Cancel')}</Button>
          <Button color="secondary" onClick={handleSearch}>
            {t_i18n('Search')}
          </Button>
        </DialogActions>
      </Dialog>
    </React.Fragment>
  );
};

export default DialogFilters;
