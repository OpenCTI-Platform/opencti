import React, { useState } from 'react';
import * as R from 'ramda';
import { useNavigate } from 'react-router-dom-v5-compat';
import { useFormatter } from '../../../../components/i18n';
import { FiltersVariant, isUniqFilter, onlyGroupOrganization } from '../../../../utils/filters/filtersUtils';
import FiltersElement from './FiltersElement';
import ListFilters from './ListFilters';
import DialogFilters from './DialogFilters';
import SearchScopeElement from './SearchScopeElement';
import useSearchEntities from '../../../../utils/filters/useSearchEntities';

const Filters = ({
  variant,
  disabled,
  size,
  fontSize,
  availableFilterKeys,
  noDirectFilters,
  availableEntityTypes,
  availableRelationshipTypes,
  allEntityTypes,
  handleAddFilter,
}) => {
  const { nsd } = useFormatter();

  const navigate = useNavigate();

  const [open, setOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState(null);

  const [inputValues, setInputValues] = useState({});
  const [filters, setFilters] = useState({});

  const [keyword, setKeyword] = useState('');
  const [searchScope, setSearchScope] = useState({});

  const [entities, searchEntities] = useSearchEntities({
    searchScope,
    setInputValues,
    availableEntityTypes,
    availableRelationshipTypes,
    allEntityTypes,
  });

  const handleOpenFilters = (event) => {
    setOpen(true);
    setAnchorEl(event.currentTarget);
  };
  const handleCloseFilters = () => {
    setOpen(false);
    setAnchorEl(null);
  };

  const defaultHandleAddFilter = handleAddFilter || ((key, id, value, event = null) => {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if ((filters[key] ?? []).length > 0) {
      setFilters((c) => ({
        ...c,
        [key]: isUniqFilter(key)
          ? [{ id, value }]
          : R.uniqBy(R.prop('id'), [
            { id, value },
            ...c[key],
          ]),
      }));
    } else {
      setFilters((c) => ({ ...c, [key]: [{ id, value }] }));
    }
  });
  const handleRemoveFilter = (key) => setFilters((c) => R.dissoc(key, c));

  const handleSearch = () => {
    handleCloseFilters();
    const urlParams = { filters: JSON.stringify(filters) };
    navigate(
      `/dashboard/search${
        keyword.length > 0 ? `/${keyword}` : ''
      }?${new URLSearchParams(urlParams).toString()}`,
    );
  };

  const handleChange = (filterKey, event, value) => {
    if (value) {
      const group = !onlyGroupOrganization.includes(filterKey) ? value.group : undefined;
      const filterAdd = `${filterKey}${group ? `_${group}` : ''}`;
      defaultHandleAddFilter(filterAdd, value.value, value.label, event);
    }
  };

  const handleChangeKeyword = (event) => setKeyword(event.target.value);

  const handleChangeDate = (filterKey, date) => {
    setInputValues((c) => ({ ...c, [filterKey]: date }));
  };

  const handleAcceptDate = (filterKey, date) => {
    if (date && date.toISOString()) {
      defaultHandleAddFilter(filterKey, date.toISOString(), nsd(date));
    }
  };

  const handleValidateDate = (filterKey, event) => {
    if (event.key === 'Enter') {
      if (inputValues[filterKey].toString() !== 'Invalid Date') {
        return handleAcceptDate(
          filterKey,
          inputValues[filterKey],
        );
      }
    }
    return null;
  };

  const renderSearchScopeSelection = (key) => (
    <SearchScopeElement
      name={key}
      searchScope={searchScope}
      setSearchScope={setSearchScope}
    />
  );

  const filterElement = (
    <FiltersElement
      variant={variant}
      keyword={keyword}
      availableFilterKeys={availableFilterKeys}
      handleChangeKeyword={handleChangeKeyword}
      handleChangeDate={handleChangeDate}
      handleAcceptDate={handleAcceptDate}
      handleValidateDate={handleValidateDate}
      noDirectFilters={noDirectFilters}
      inputValues={inputValues}
      searchScope={searchScope}
      entities={entities}
      handleChange={handleChange}
      searchEntities={searchEntities}
      renderSearchScopeSelection={renderSearchScopeSelection}
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
        handleRemoveFilter={handleRemoveFilter}
        handleSearch={handleSearch}
        filterElement={filterElement}
      />
    );
  }
  return (
    <ListFilters
      size={size}
      fontSize={fontSize}
      handleOpenFilters={handleOpenFilters}
      handleCloseFilters={handleCloseFilters}
      open={open}
      anchorEl={anchorEl}
      noDirectFilters={noDirectFilters}
      availableFilterKeys={availableFilterKeys}
      searchScope={searchScope}
      entities={entities}
      inputValues={inputValues}
      renderSearchScopeSelection={renderSearchScopeSelection}
      filterElement={filterElement}
      variant={variant}
      searchEntities={searchEntities}
      handleChange={handleChange}
    />
  );
};

export default Filters;
