import React from 'react';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { BiotechOutlined } from '@mui/icons-material';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import * as R from 'ramda';
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
  handleRemoveFilter,
  handleSearch,
  filterElement,
}) => {
  const { t } = useFormatter();
  return (
    <React.Fragment>
      <Tooltip title={t('Advanced search')}>
        <IconButton
          onClick={handleOpenFilters}
          disabled={disabled}
          size={size || 'medium'}
        >
          <BiotechOutlined fontSize={fontSize || 'medium'} />
        </IconButton>
      </Tooltip>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={open}
        onClose={handleCloseFilters}
        fullWidth={true}
        maxWidth="md"
      >
        <DialogTitle>{t('Advanced search')}</DialogTitle>
        <DialogContent style={{ paddingTop: 10 }}>
          {!R.isEmpty(filters) && (
            <FilterIconButton
              filters={filters}
              handleRemoveFilter={handleRemoveFilter}
              classNameNumber={4}
              styleNumber={2}
            />
          )}
          {filterElement}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseFilters}>{t('Cancel')}</Button>
          <Button color="secondary" onClick={handleSearch}>
            {t('Search')}
          </Button>
        </DialogActions>
      </Dialog>
    </React.Fragment>
  );
};

export default DialogFilters;
