import Button from '@mui/material/Button';
import { FilterListOffOutlined, FilterListOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Popover from '@mui/material/Popover';
import Tooltip from '@mui/material/Tooltip';
import { RayEndArrow, RayStartArrow } from 'mdi-material-ui';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import TextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { useFormatter } from '../../../../components/i18n';
import { useBuildFilterKeysMapFromEntityType, getDefaultFilterObject } from '../../../../utils/filters/filtersUtils';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    width: 600,
    padding: 20,
  },
}));

const ListFilters = ({
  size,
  fontSize,
  handleOpenFilters,
  handleCloseFilters,
  open,
  anchorEl,
  availableFilterKeys,
  filterElement,
  variant,
  type,
  helpers,
  required = false,
  entityTypes,
}) => {
  const { t_i18n } = useFormatter();
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);
  const [inputValue, setInputValue] = React.useState('');
  const classes = useStyles();
  let icon = <FilterListOutlined fontSize={fontSize || 'medium'} />;
  let tooltip = t_i18n('Filters');
  let placeholder = t_i18n('Add filter');
  let color = 'primary';
  if (type === 'from') {
    icon = <RayStartArrow fontSize={fontSize || 'medium'} />;
    tooltip = t_i18n('Dynamic source filters');
    placeholder = t_i18n('Dynamic source filters');
    color = 'warning';
  } else if (type === 'to') {
    icon = <RayEndArrow fontSize={fontSize || 'medium'} />;
    tooltip = t_i18n('Dynamic target filters');
    placeholder = t_i18n('Dynamic target filters');
    color = 'success';
  }
  const handleClearFilters = () => {
    helpers.handleClearAllFilters();
  };
  const handleChange = (value) => {
    helpers.handleAddFilterWithEmptyValue(getDefaultFilterObject(value, filterKeysMap.get(value)));
  };
  const isNotUniqEntityTypes = (entityTypes.length === 1 && ['Stix-Core-Object', 'Stix-Domain-Object', 'Stix-Cyber-Observable', 'Container'].includes(entityTypes[0]))
    || (entityTypes.length > 1);
  const options = isNotUniqEntityTypes
    ? availableFilterKeys
      .map((key) => {
        const subEntityTypes = filterKeysMap.get(key)?.subEntityTypes ?? [];
        const isFilterKeyForAllTypes = (entityTypes.length === 1 && subEntityTypes.some((subType) => entityTypes.includes(subType)))
          || (entityTypes.length > 1 && entityTypes.every((subType) => subEntityTypes.includes(subType)));
        return {
          value: key,
          label: t_i18n(filterKeysMap.get(key)?.label ?? key),
          numberOfOccurences: subEntityTypes.length,
          // eslint-disable-next-line no-nested-ternary
          groupLabel: isFilterKeyForAllTypes
            ? t_i18n('Most used filters')
            : t_i18n('All other filters'),
          groupOrder: isFilterKeyForAllTypes ? 1 : 0,
        };
      })
      .sort((a, b) => a.label.localeCompare(b.label))
      .sort((a, b) => b.groupOrder - a.groupOrder) // 'Most used filters' before 'All other filters'
    : availableFilterKeys
      .map((key) => {
        return {
          value: key,
          label: t_i18n(filterKeysMap.get(key)?.label ?? key),
        };
      })
      .sort((a, b) => a.label.localeCompare(b.label));
  return (
    <>
      {variant === 'text' ? (
        <Tooltip title={tooltip}>
          <Button
            variant="contained"
            color={color}
            onClick={handleOpenFilters}
            startIcon={icon}
            size="small"
          >
            {t_i18n('Filters')}
          </Button>
        </Tooltip>
      ) : (
        <>
          <MUIAutocomplete
            options={options}
            groupBy={isNotUniqEntityTypes ? (option) => option.groupLabel : undefined}
            sx={{ width: 200 }}
            value={null}
            onChange={(event, selectOptionValue) => {
              handleChange(selectOptionValue.value);
            }}
            inputValue={inputValue}
            onInputChange={(event, newValue, reason) => {
              if (reason === 'reset') {
                return;
              }
              setInputValue(newValue);
            }}
            renderInput={(params) => (
              <TextField
                {...params}
                variant="outlined"
                size="small"
                label={placeholder}
                required={required}
              />
            )}
            renderOption={(props, option) => <li {...props}>{option.label}</li>}
          />
          <Tooltip title={t_i18n('Clear filters')}>
            <IconButton
              color={color}
              onClick={handleClearFilters}
              size={size || 'small'}
            >
              <FilterListOffOutlined fontSize={size || 'small'} />
            </IconButton>
          </Tooltip>
        </>
      )}
      <Popover
        classes={{ paper: classes.container }}
        open={open}
        anchorEl={anchorEl}
        onClose={handleCloseFilters}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'center',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'center',
        }}
        elevation={1}
        className="noDrag"
      >
        {filterElement}
      </Popover>
    </>
  );
};

export default ListFilters;
