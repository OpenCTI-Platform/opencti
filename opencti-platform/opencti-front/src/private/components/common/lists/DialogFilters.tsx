import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { BiotechOutlined } from '@mui/icons-material';
import DialogTitle from '@mui/material/DialogTitle';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import Tooltip from '@mui/material/Tooltip';
import React, { FunctionComponent, ReactElement } from 'react';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import { Filter, FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { FilterSearchContext } from '../../../../utils/filters/filtersUtils';
import { SURFACE_LAYER, fdsLayerClass, layerInputVars } from '../../../../utils/fdsLayer';

interface DialogFiltersProps {
  handleOpenFilters: (event: React.SyntheticEvent) => void;
  disabled?: boolean;
  open: boolean;
  filters?: FilterGroup;
  handleCloseFilters: () => void;
  defaultHandleRemoveFilter: (key: string, id?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  handleSearch: () => void;
  filterElement: ReactElement;
  searchContext?: FilterSearchContext;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
}

const DialogFilters: FunctionComponent<DialogFiltersProps> = ({
  handleOpenFilters,
  disabled,
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
          aria-label={t_i18n('Advanced search')}
        >
          <BiotechOutlined fontSize="medium" />
        </IconButton>
      </Tooltip>
      <Dialog
        // A dialog is a layer-2 surface, like a drawer. See utils/fdsLayer.ts.
        slotProps={{ paper: { className: fdsLayerClass(SURFACE_LAYER), sx: { ...layerInputVars } } }}
        open={open}
        onClose={handleCloseFilters}
      >
        {/* A real DialogTitle. */}
        <DialogTitle>{t_i18n('Advanced search')}</DialogTitle>
        <FilterIconButton
          filters={filters}
          handleRemoveFilter={defaultHandleRemoveFilter}
          handleSwitchGlobalMode={handleSwitchGlobalMode}
          handleSwitchLocalMode={handleSwitchLocalMode}
          searchContext={searchContext}
          availableEntityTypes={availableEntityTypes}
          availableRelationshipTypes={availableRelationshipTypes}
        />
        {filterElement}
        <DialogActions>
          <Button variant="secondary" onClick={handleCloseFilters}>{t_i18n('Cancel')}</Button>
          <Button onClick={handleSearch}>
            {t_i18n('Search')}
          </Button>
        </DialogActions>
      </Dialog>
    </React.Fragment>
  );
};

export default DialogFilters;
