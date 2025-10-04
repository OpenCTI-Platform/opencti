import React, { FunctionComponent, ReactElement } from 'react';
import { BiotechOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import FilterIconButton from '../../../../components/FilterIconButton';
import { Filter, FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { FilterSearchContext } from '../../../../utils/filters/filtersUtils';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, Tooltip } from '@components';
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
          size={'medium'}
        >
          <BiotechOutlined fontSize={'medium'} />
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
