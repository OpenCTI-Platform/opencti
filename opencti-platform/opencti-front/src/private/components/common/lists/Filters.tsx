import React, { ChangeEvent, FunctionComponent, useState } from 'react';
import { useNavigate } from 'react-router';
import ListFiltersWithoutLocalStorage from '@components/common/lists/ListFiltersWithoutLocalStorage';
import { uniq } from 'ramda';
import {
  constructHandleAddFilter,
  constructHandleRemoveFilter,
  emptyFilterGroup,
  FilterSearchContext,
  FiltersVariant,
  canonicalizeFilterGroupForBackend,
} from '../../../../utils/filters/filtersUtils';
import FiltersElement, { FilterElementsInputValue } from './FiltersElement';
import ListFilters from './ListFilters';
import DialogFilters from './DialogFilters';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import useAuth from '../../../../utils/hooks/useAuth';
import { Filter, FilterGroup, handleFilterHelpers } from '../../../../utils/filters/filtersHelpers-types';

interface FiltersProps {
  variant?: string;
  isDatatable?: boolean;
  disabled?: boolean;
  availableFilterKeys: string[];
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  handleAddFilter?: HandleAddFilter;
  handleRemoveFilter?: (key: string, id?: string) => void;
  handleSwitchFilter?: HandleAddFilter;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  handleFiltersChange?: (currentFilter: FilterGroup | undefined) => void;
  searchContext?: FilterSearchContext;
  type?: string;
  helpers?: handleFilterHelpers;
  required?: boolean;
  hideSavedFilters?: boolean;
  disableAddFilterGroup?: boolean;
}

/**
 * Builds the url search params holding the filters of the knowledge search,
 * stripping the frontend-only ids at any depth.
 */
export const buildSearchFiltersUrlParams = (filters?: FilterGroup) => ({
  filters: JSON.stringify(filters ? canonicalizeFilterGroupForBackend(filters) : filters),
});

const Filters: FunctionComponent<FiltersProps> = ({
  variant,
  isDatatable,
  disabled,
  availableFilterKeys,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  handleAddFilter,
  handleRemoveFilter,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  handleFiltersChange,
  searchContext,
  type,
  helpers,
  required = false,
  hideSavedFilters = false,
  disableAddFilterGroup = false,
}) => {
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [filters, setFilters] = useState<FilterGroup | undefined>(emptyFilterGroup);
  const [inputValues, setInputValues] = useState<FilterElementsInputValue[]>(
    [],
  );
  const [keyword, setKeyword] = useState('');
  const entityTypes: string[] = searchContext?.entityTypes ?? ['Stix-Core-Object'];

  const handleOpenFilters = (event: React.SyntheticEvent) => {
    setIsOpen(true);
    setAnchorEl(event.currentTarget);
  };
  const handleCloseFilters = () => {
    setIsOpen(false);
    setAnchorEl(null);
  };
  const { filterKeysSchema } = useAuth().schema;
  const defaultHandleAddFilter = handleAddFilter
    || ((key, id, operator = 'eq', event = undefined) => {
      if (event) {
        event.stopPropagation();
        event.preventDefault();
      }
      if (handleFiltersChange) {
        handleFiltersChange(constructHandleAddFilter(filters, key, id, filterKeysSchema, operator));
      } else {
        setFilters(constructHandleAddFilter(filters, key, id, filterKeysSchema, operator));
      }
    });
  const defaultHandleRemoveFilter = handleRemoveFilter
    || ((key, operator = 'eq') => {
      if (handleFiltersChange) {
        handleFiltersChange(constructHandleRemoveFilter(filters, key, operator));
      } else {
        setFilters(constructHandleRemoveFilter(filters, key, operator));
      }
    });
  const handleSearch = () => {
    handleCloseFilters();
    const urlParams = buildSearchFiltersUrlParams(filters);
    navigate(
      `/dashboard/search/knowledge${
        keyword.length > 0 ? `/${keyword}` : ''
      }?${new URLSearchParams(urlParams).toString()}`,
    );
  };
  const handleChangeKeyword = (event: ChangeEvent) => setKeyword((event.target as HTMLInputElement).value);
  const filterElement = (
    <FiltersElement
      variant={variant}
      disabled={disabled}
      keyword={keyword}
      availableFilterKeys={availableFilterKeys}
      searchContext={searchContext ?? { entityTypes }}
      handleChangeKeyword={handleChangeKeyword}
      inputValues={inputValues}
      setInputValues={setInputValues}
      defaultHandleAddFilter={defaultHandleAddFilter}
      availableEntityTypes={availableEntityTypes}
      availableRelationshipTypes={availableRelationshipTypes}
      availableRelationFilterTypes={availableRelationFilterTypes}
    />
  );
  if (variant === FiltersVariant.dialog) {
    return (
      <DialogFilters
        handleOpenFilters={handleOpenFilters}
        disabled={disabled}
        open={isOpen}
        filters={filters}
        handleCloseFilters={handleCloseFilters}
        defaultHandleRemoveFilter={defaultHandleRemoveFilter}
        handleSwitchGlobalMode={handleSwitchGlobalMode}
        handleSwitchLocalMode={handleSwitchLocalMode}
        handleSearch={handleSearch}
        filterElement={filterElement}
        searchContext={searchContext}
        availableEntityTypes={availableEntityTypes}
        availableRelationshipTypes={availableRelationshipTypes}
      />
    );
  }
  return (
    <>
      {helpers ? (
        <ListFilters
          handleOpenFilters={handleOpenFilters}
          handleCloseFilters={handleCloseFilters}
          isOpen={isOpen}
          anchorEl={anchorEl}
          availableFilterKeys={uniq(availableFilterKeys)}
          filterElement={filterElement}
          variant={variant}
          type={type}
          helpers={helpers}
          required={required}
          entityTypes={entityTypes}
          isDatatable={isDatatable}
          disabled={disabled}
          hideSavedFilters={hideSavedFilters}
          disableAddFilterGroup={disableAddFilterGroup}
        />
      ) : (
        <ListFiltersWithoutLocalStorage
          handleOpenFilters={handleOpenFilters}
          handleCloseFilters={handleCloseFilters}
          open={isOpen}
          anchorEl={anchorEl}
          filterElement={filterElement}
          variant={variant}
          type={type}
        />
      )}
    </>
  );
};

export default Filters;
