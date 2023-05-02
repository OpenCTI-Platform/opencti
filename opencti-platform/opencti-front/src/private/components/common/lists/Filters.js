import PropTypes from 'prop-types';
import * as R from 'ramda';
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom-v5-compat';
import { FiltersVariant, isUniqFilter } from '../../../../utils/filters/filtersUtils';
import DialogFilters from './DialogFilters';
import FiltersElement from './FiltersElement';
import ListFilters from './ListFilters';

const Filters = ({
  variant,
  disabled,
  size,
  fontSize,
  availableFilterKeys,
  noDirectFilters,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  allEntityTypes,
  handleAddFilter,
  type,
}) => {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState(null);
  const [filters, setFilters] = useState({});
  const [inputValues, setInputValues] = useState({});
  const [keyword, setKeyword] = useState('');

  const handleOpenFilters = (event) => {
    setOpen(true);
    setAnchorEl(event.currentTarget);
  };
  const handleCloseFilters = () => {
    setOpen(false);
    setAnchorEl(null);
  };
  const defaultHandleAddFilter = handleAddFilter
    || ((key, id, value, event = null) => {
      if (event) {
        event.stopPropagation();
        event.preventDefault();
      }
      if ((filters[key] ?? []).length > 0) {
        setFilters((c) => ({
          ...c,
          [key]: isUniqFilter(key)
            ? [{ id, value }]
            : R.uniqBy(R.prop('id'), [{ id, value }, ...c[key]]),
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
  const handleChangeKeyword = (event) => setKeyword(event.target.value);

  const filterElement = (
    <FiltersElement
      variant={variant}
      keyword={keyword}
      availableFilterKeys={availableFilterKeys}
      handleChangeKeyword={handleChangeKeyword}
      noDirectFilters={noDirectFilters}
      inputValues={inputValues}
      setInputValues={setInputValues}
      defaultHandleAddFilter={defaultHandleAddFilter}
      availableEntityTypes={availableEntityTypes}
      availableRelationshipTypes={availableRelationshipTypes}
      availableRelationFilterTypes={availableRelationFilterTypes}
      allEntityTypes={allEntityTypes}
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
        type={type}
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
      filterElement={filterElement}
      variant={variant}
      type={type}
      inputValues={inputValues}
      setInputValues={setInputValues}
      defaultHandleAddFilter={defaultHandleAddFilter}
      availableEntityTypes={availableEntityTypes}
      availableRelationshipTypes={availableRelationshipTypes}
      availableRelationFilterTypes={availableRelationFilterTypes}
      allEntityTypes={allEntityTypes}
    />
  );
};

Filters.propTypes = {
  variant: PropTypes.string.isRequired,
  disabled: PropTypes.bool,
  size: PropTypes.string,
  fontSize: PropTypes.string,
  availableFilterKeys: PropTypes.arrayOf(PropTypes.string).isRequired,
  noDirectFilters: PropTypes.bool,
  availableEntityTypes: PropTypes.arrayOf(PropTypes.string),
  availableRelationshipTypes: PropTypes.arrayOf(PropTypes.string),
  availableRelationFilterTypes: PropTypes.arrayOf(PropTypes.string),
  allEntityTypes: PropTypes.bool,
  handleAddFilter: PropTypes.func.isRequired,
  type: PropTypes.string,
};

export default Filters;
