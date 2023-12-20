import React, { ChangeEvent, FunctionComponent, useState } from 'react';
import { useNavigate } from 'react-router-dom-v5-compat';
import ListFiltersWithoutLocalStorage from '@components/common/lists/ListFiltersWithoutLocalStorage';
import { constructHandleAddFilter, constructHandleRemoveFilter, emptyFilterGroup, Filter, FilterGroup, FiltersVariant } from '../../../../utils/filters/filtersUtils';
import FiltersElement, { FilterElementsInputValue } from './FiltersElement';
import ListFilters from './ListFilters';
import DialogFilters from './DialogFilters';
import { HandleAddFilter, handleFilterHelpers } from '../../../../utils/hooks/useLocalStorage';
import { setSearchEntitiesScope } from '../../../../utils/filters/SearchEntitiesUtil';

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
  searchContext?: {
    entityTypes: string[];
    elementId?: string[];
  };
  type?: string;
  helpers?: handleFilterHelpers;
  entityType?: string;
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
  entityType,
}) => {
  console.log('searchContext', searchContext);
  console.log('entityTYpe', entityType);
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
  const [searchScope, _] = useState<Record<string, string[]>>(
    availableRelationFilterTypes || {
      targets: [
        'Region',
        'Country',
        'Administrative-Area',
        'City',
        'Position',
        'Sector',
        'Organization',
        'Individual',
        'System',
        'Event',
        'Vulnerability',
      ],
    },
  );
  const entityTypes = entityType ? [entityType] : ['Stix-Core-Object'];
  setSearchEntitiesScope({
    searchContext: searchContext ?? { entityTypes },
    searchScope,
    setInputValues: setInputValues as (
      value: {
        key: string;
        values: string[];
        operator?: string;
      }[],
    ) => void,
    availableEntityTypes,
    availableRelationshipTypes,
  });
  const handleOpenFilters = (event: React.SyntheticEvent) => {
    setOpen(true);
    setAnchorEl(event.currentTarget);
  };
  const handleCloseFilters = () => {
    setOpen(false);
    setAnchorEl(null);
  };
  const defaultHandleAddFilter = handleAddFilter
    || ((key, id, operator = 'eq', event = undefined) => {
      if (event) {
        event.stopPropagation();
        event.preventDefault();
      }
      setFilters(constructHandleAddFilter(filters, key, id, operator));
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
      entityType={entityType}
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
          availableFilterKeys={availableFilterKeys}
          filterElement={filterElement}
          variant={variant}
          type={type}
          helpers={helpers}
          entityType={entityType}
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
