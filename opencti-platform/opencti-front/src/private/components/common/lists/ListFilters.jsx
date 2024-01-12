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
import { getDefaultFilterObject } from '../../../../utils/filters/filtersUtils';

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
}) => {
  const { t } = useFormatter();
  const [inputValue, setInputValue] = React.useState('');
  const classes = useStyles();
  let icon = <FilterListOutlined fontSize={fontSize || 'medium'} />;
  let tooltip = t('Filters');
  let placeholder = t('Add filter');
  let color = 'primary';
  if (type === 'from') {
    icon = <RayStartArrow fontSize={fontSize || 'medium'} />;
    tooltip = t('Dynamic source filters');
    placeholder = t('Dynamic source filters');
    color = 'warning';
  } else if (type === 'to') {
    icon = <RayEndArrow fontSize={fontSize || 'medium'} />;
    tooltip = t('Dynamic target filters');
    placeholder = t('Dynamic target filters');
    color = 'success';
  }
  const handleClearFilters = () => {
    helpers.handleClearAllFilters();
  };
  const handleChange = (value) => {
    helpers.handleAddFilterWithEmptyValue(getDefaultFilterObject(value));
  };
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
            {t('Filters')}
          </Button>
        </Tooltip>
      ) : (
        <>
          <MUIAutocomplete
            id="list-filters-combo-box"
            options={availableFilterKeys
              .map((opt) => ({
                value: opt,
                label: t(opt),
              }))
              .sort((a, b) => a.label.localeCompare(b.label))}
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
              />
            )}
            renderOption={(props, option) => <li {...props}>{option.label}</li>}
          />
          <Tooltip title={t('Clear filters')}>
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
