import React, { ChangeEvent, FunctionComponent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import ListFiltersWithoutLocalStorage from '@components/common/lists/ListFiltersWithoutLocalStorage';
import { uniq } from 'ramda';
import { constructHandleAddFilter, constructHandleRemoveFilter, emptyFilterGroup, FilterSearchContext, FiltersVariant } from '../../../../utils/filters/filtersUtils';
import FiltersElement, { FilterElementsInputValue } from './FiltersElement';
import ListFilters from './ListFilters';
import DialogFilters from './DialogFilters';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import useAuth from '../../../../utils/hooks/useAuth';
import { Filter, FilterGroup, handleFilterHelpers } from '../../../../utils/filters/filtersHelpers-types';

interface FiltersProps {
  variant?: string;
  disabled?: boolean;
  size?: number;
  fontSize?: number;
  availableFilterKeys: string[];
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  handleAddFilter?: HandleAddFilter;
  handleRemoveFilter?: (key: string, id?: string) => void;
  handleSwitchFilter?: HandleAddFilter;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  searchContext?: FilterSearchContext
  type?: string;
  helpers?: handleFilterHelpers;
}

const Filters: FunctionComponent<FiltersProps> = ({
  variant,
  disabled,
  size,
  fontSize,
  availableFilterKeys,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  handleAddFilter,
  handleRemoveFilter,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  searchContext,
  type,
  helpers,
}) => {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [filters, setFilters] = useState<FilterGroup | undefined>(
    emptyFilterGroup,
  );
  const [inputValues, setInputValues] = useState<FilterElementsInputValue[]>(
    [],
  );
  const [keyword, setKeyword] = useState('');
  const entityTypes = searchContext?.entityTypes ?? ['Stix-Core-Object'];
  const handleOpenFilters = (event: React.SyntheticEvent) => {
    setOpen(true);
    setAnchorEl(event.currentTarget);
  };
  const handleCloseFilters = () => {
    setOpen(false);
    setAnchorEl(null);
  };
  const { filterKeysSchema } = useAuth().schema;
  const defaultHandleAddFilter = handleAddFilter
    || ((key, id, operator = 'eq', event = undefined) => {
      if (event) {
        event.stopPropagation();
        event.preventDefault();
      }
      setFilters(constructHandleAddFilter(filters, key, id, filterKeysSchema, operator));
    });
  const defaultHandleRemoveFilter = handleRemoveFilter
    || ((key, operator = 'eq') => {
      setFilters(constructHandleRemoveFilter(filters, key, operator));
    });
  const handleSearch = () => {
    handleCloseFilters();
    const urlParams = { filters: JSON.stringify(filters) };
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
        size={size}
        fontSize={fontSize}
        open={open}
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
          size={size}
          fontSize={fontSize}
          handleOpenFilters={handleOpenFilters}
          handleCloseFilters={handleCloseFilters}
          open={open}
          anchorEl={anchorEl}
          availableFilterKeys={uniq(availableFilterKeys)}
          filterElement={filterElement}
          variant={variant}
          type={type}
          helpers={helpers}
          entityTypes={entityTypes}
        />
      ) : (
        <ListFiltersWithoutLocalStorage
          size={size}
          fontSize={fontSize}
          handleOpenFilters={handleOpenFilters}
          handleCloseFilters={handleCloseFilters}
          open={open}
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
