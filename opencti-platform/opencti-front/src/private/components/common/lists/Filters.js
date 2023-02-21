import React, { useState } from 'react';
import * as R from 'ramda';
import { useNavigate } from 'react-router-dom-v5-compat';
import { FiltersVariant, isUniqFilter } from '../../../../utils/filters/filtersUtils';
import FiltersElement from './FiltersElement';
import ListFilters from './ListFilters';
import DialogFilters from './DialogFilters';
import { isNotEmptyField } from '../../../../utils/utils';

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
  usedFilters = {},
}) => {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState(null);
  const [inputValues, setInputValues] = useState({});
  const [filters, setFilters] = useState({});
  const [keyword, setKeyword] = useState('');

  const handleUpdateDateInputValues = (filtersToApply) => {
    if (filtersToApply) {
      const filtersToApplyDateKeys = Object.keys(filtersToApply).filter((key) => key.endsWith('date'));
      const inputValuesDateKeys = Object.keys(inputValues).filter((key) => key.endsWith('date'));
      const keysToRemove = inputValuesDateKeys.map((inputKey) => {
        if (!filtersToApplyDateKeys.includes(inputKey)) {
          return (inputKey);
        }
        return null;
      }).filter((n) => n !== null);
      if (isNotEmptyField(keysToRemove)) {
        let newInputValues = inputValues;
        // eslint-disable-next-line no-return-assign
        keysToRemove.map((key) => newInputValues = R.dissoc(key, newInputValues));
        setInputValues(newInputValues);
      }
      const keysToAdd = filtersToApplyDateKeys.map((filterKey) => {
        if (!inputValuesDateKeys.includes(filterKey)) {
          return (filterKey);
        }
        return null;
      }).filter((n) => n !== null);
      if (isNotEmptyField(keysToAdd)) {
        let newInputValues = inputValues;
        // eslint-disable-next-line array-callback-return
        keysToAdd.map((key) => {
          newInputValues = {
            ...newInputValues,
            [key]: new Date(filtersToApply[key].map((n) => n.id)[0]),
          };
        });
        setInputValues(newInputValues);
      }
    } else if (isNotEmptyField(inputValues)) {
      setInputValues({});
    }
  };

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

  if (variant === FiltersVariant.dialog) {
    handleUpdateDateInputValues(filters);
  } else {
    handleUpdateDateInputValues(usedFilters);
  }

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

export default Filters;
