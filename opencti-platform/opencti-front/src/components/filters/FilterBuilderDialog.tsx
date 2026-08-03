import React, { FunctionComponent, useEffect, useMemo, useState } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { AccountTreeOutlined } from '@mui/icons-material';
import { usePreloadedQuery, PreloadedQuery } from 'react-relay';
import FilterBuilderGroup from './FilterBuilderGroup';
import { FilterRepresentative } from './FiltersModel';
import { filterValuesContentQuery } from '../FilterValuesContent';
import { FilterValuesContentQuery } from '../__generated__/FilterValuesContentQuery.graphql';
import { useFormatter } from '../i18n';
import Transition from '../Transition';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import { Filter, FilterGroup, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import { DEFAULT_WITHIN_FILTER_VALUES, emptyFilterGroup, FilterSearchContext, normalizeFilterGroupForBackend } from '../../utils/filters/filtersUtils';
import {
  addFilterAtPath,
  addSubGroupAtPath,
  ensureFilterGroupIds,
  flattenFilters,
  FilterGroupPath,
  removeFilterInTree,
  removeGroupAtPath,
  setGroupModeAtPath,
  updateFilterInTree,
} from '../../utils/filters/filterBuilderUtils';

interface FilterBuilderDialogProps {
  open: boolean;
  onClose: () => void;
  initialFilters: FilterGroup;
  onSubmit: (filters: FilterGroup) => void;
  availableFilterKeys: string[];
  entityTypes: string[];
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  searchContext?: FilterSearchContext;
}

interface FilterBuilderContentProps extends Omit<FilterBuilderDialogProps, 'open' | 'initialFilters' | 'onSubmit'> {
  queryRef: PreloadedQuery<FilterValuesContentQuery>;
  localFilters: FilterGroup;
  helpers: handleFilterHelpers;
  onSetMode: (path: FilterGroupPath, mode: string) => void;
  onAddFilter: (path: FilterGroupPath, filter: Filter) => void;
  onAddGroup: (path: FilterGroupPath) => void;
  onRemoveGroup: (path: FilterGroupPath) => void;
  onRemoveFilter: (id: string) => void;
}

const FilterBuilderContent: FunctionComponent<FilterBuilderContentProps> = ({
  queryRef,
  localFilters,
  helpers,
  availableFilterKeys,
  entityTypes,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  searchContext,
  onSetMode,
  onAddFilter,
  onAddGroup,
  onRemoveGroup,
  onRemoveFilter,
}) => {
  const { filtersRepresentatives } = usePreloadedQuery<FilterValuesContentQuery>(
    filterValuesContentQuery,
    queryRef,
  );
  const filtersRepresentativesMap = new Map<string, FilterRepresentative>(
    filtersRepresentatives.map((n: FilterRepresentative) => [n.id, n]),
  );
  const flatFilters = flattenFilters(localFilters);

  return (
    <FilterBuilderGroup
      group={localFilters}
      path={[]}
      flatFilters={flatFilters}
      helpers={helpers}
      filtersRepresentativesMap={filtersRepresentativesMap}
      entityTypes={entityTypes}
      availableFilterKeys={availableFilterKeys}
      availableEntityTypes={availableEntityTypes}
      availableRelationshipTypes={availableRelationshipTypes}
      availableRelationFilterTypes={availableRelationFilterTypes}
      searchContext={searchContext}
      onSetMode={onSetMode}
      onAddFilter={onAddFilter}
      onAddGroup={onAddGroup}
      onRemoveGroup={onRemoveGroup}
      onRemoveFilter={onRemoveFilter}
    />
  );
};

const FilterBuilderDialog: FunctionComponent<FilterBuilderDialogProps> = ({
  open,
  onClose,
  initialFilters,
  onSubmit,
  availableFilterKeys,
  entityTypes,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  searchContext,
}) => {
  const { t_i18n } = useFormatter();
  const [localFilters, setLocalFilters] = useState<FilterGroup>(emptyFilterGroup);

  // Reset the working copy each time the dialog is (re)opened.
  useEffect(() => {
    if (open) {
      setLocalFilters(ensureFilterGroupIds(initialFilters ?? emptyFilterGroup));
    }
  }, [open]);

  const onSetMode = (path: FilterGroupPath, mode: string) => setLocalFilters((prev) => setGroupModeAtPath(prev, path, mode));
  const onAddFilter = (path: FilterGroupPath, filter: Filter) => setLocalFilters((prev) => addFilterAtPath(prev, path, filter));
  const onAddGroup = (path: FilterGroupPath) => setLocalFilters((prev) => addSubGroupAtPath(prev, path));
  const onRemoveGroup = (path: FilterGroupPath) => setLocalFilters((prev) => removeGroupAtPath(prev, path));
  const onRemoveFilter = (id: string) => setLocalFilters((prev) => removeFilterInTree(prev, id));

  // Recursive helpers so the shared FilterChipPopover can edit a filter's values
  // wherever it sits in the nested tree (matching by filter id).
  const helpers: handleFilterHelpers = useMemo(() => ({
    getLatestAddFilterId: () => undefined,
    handleAddFilterWithEmptyValue: (filter: Filter) => setLocalFilters((prev) => addFilterAtPath(prev, [], filter)),
    handleAddRepresentationFilter: (id, value) => setLocalFilters((prev) => updateFilterInTree(prev, id, (f) => ({ ...f, values: [...f.values, value] }))),
    handleAddSingleValueFilter: (id, valueId) => setLocalFilters((prev) => updateFilterInTree(prev, id, (f) => ({ ...f, values: valueId ? [valueId] : [] }))),
    handleReplaceFilterValues: (id, values) => setLocalFilters((prev) => updateFilterInTree(prev, id, (f) => ({ ...f, values }))),
    handleRemoveRepresentationFilter: (id, value) => setLocalFilters((prev) => updateFilterInTree(
      prev,
      id,
      (f) => ({ ...f, values: f.values.filter((v: unknown) => v !== value) }),
    )),
    handleChangeRepresentationFilter: (id, oldValue, newValue) => setLocalFilters((prev) => {
      if (oldValue && newValue) {
        return updateFilterInTree(prev, id, (f) => ({ ...f, values: f.values.filter((v: unknown) => v !== oldValue).concat([newValue]) }));
      }
      if (oldValue) {
        return updateFilterInTree(prev, id, (f) => ({ ...f, values: f.values.filter((v: unknown) => v !== oldValue) }));
      }
      if (newValue) {
        return updateFilterInTree(prev, id, (f) => ({ ...f, values: [...f.values, newValue] }));
      }
      return prev;
    }),
    handleChangeOperatorFilters: (id, operator) => setLocalFilters((prev) => updateFilterInTree(prev, id, (f) => {
      let values = [...f.values];
      if (['nil', 'not_nil'].includes(operator)) {
        values = [];
      } else if (operator === 'within' && f.operator !== 'within') {
        values = DEFAULT_WITHIN_FILTER_VALUES;
      } else if (f.operator === 'within' && operator !== 'within') {
        values = [];
      }
      return { ...f, operator, values };
    })),
    handleSwitchLocalMode: (filter: Filter) => setLocalFilters((prev) => updateFilterInTree(prev, filter.id ?? '', (f) => ({ ...f, mode: f.mode === 'and' ? 'or' : 'and' }))),
    handleSwitchGlobalMode: () => setLocalFilters((prev) => ({ ...prev, mode: prev.mode === 'and' ? 'or' : 'and' })),
    handleRemoveFilterById: (id: string) => setLocalFilters((prev) => removeFilterInTree(prev, id)),
    handleClearAllFilters: () => setLocalFilters(emptyFilterGroup),
  }), []);

  const queryRef = useQueryLoading<FilterValuesContentQuery>(
    filterValuesContentQuery,
    { filters: normalizeFilterGroupForBackend(localFilters) },
  );

  const handleValidate = () => {
    onSubmit(localFilters);
    onClose();
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      slots={{ transition: Transition }}
      slotProps={{ paper: { elevation: 1 } }}
      fullWidth
      maxWidth="md"
    >
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.5, paddingBottom: 1 }}>
        <AccountTreeOutlined color="primary" />
        <span>{t_i18n('Advanced filter builder')}</span>
      </DialogTitle>
      <DialogContent>
        <Typography variant="body2" sx={{ color: 'text.secondary', marginBottom: 2 }}>
          {t_i18n('Combine conditions with AND / OR operators and nested groups. Click a mode pill to switch its operator.')}
        </Typography>
        <Box
          sx={{
            minHeight: 240,
            borderRadius: '8px',
            padding: 2,
            backgroundColor: 'background.default',
            border: (theme) => `1px solid ${theme.palette.divider}`,
          }}
        >
          {queryRef && (
            <React.Suspense fallback={<span />}>
              <FilterBuilderContent
                queryRef={queryRef}
                localFilters={localFilters}
                helpers={helpers}
                availableFilterKeys={availableFilterKeys}
                entityTypes={entityTypes}
                availableEntityTypes={availableEntityTypes}
                availableRelationshipTypes={availableRelationshipTypes}
                availableRelationFilterTypes={availableRelationFilterTypes}
                searchContext={searchContext}
                onClose={onClose}
                onSetMode={onSetMode}
                onAddFilter={onAddFilter}
                onAddGroup={onAddGroup}
                onRemoveGroup={onRemoveGroup}
                onRemoveFilter={onRemoveFilter}
              />
            </React.Suspense>
          )}
        </Box>
      </DialogContent>
      <DialogActions sx={{ padding: '16px 24px 24px' }}>
        <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
        <Button onClick={handleValidate}>{t_i18n('Apply')}</Button>
      </DialogActions>
    </Dialog>
  );
};

export default FilterBuilderDialog;
