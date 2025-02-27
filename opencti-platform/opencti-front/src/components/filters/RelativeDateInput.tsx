import React, { FunctionComponent, useState } from 'react';
import TextField from '@mui/material/TextField';
import { DateRangeOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import { useTheme } from '@mui/material/styles';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { Link } from 'react-router-dom';
import { useFormatter } from '../i18n';
import { isValidDate, RELATIVE_DATE_REGEX } from '../../utils/String';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

interface RelativeDateInputProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  label: string;
  valueOrder: number;
  dateInput: string[];
  setDateInput: (value: string[]) => void;
}

const RelativeDateInput: FunctionComponent<RelativeDateInputProps> = ({
  filter,
  filterKey,
  helpers,
  label,
  valueOrder,
  dateInput,
  setDateInput,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const [isDatePickerOpen, setIsDatePickerOpen] = useState(false);

  const generateErrorMessage = (values: string[]) => {
    if (values.length !== 2) {
      return t_i18n('The value must not be empty');
    }
    if (values.includes('')) {
      return t_i18n('The value must not be empty.');
    }
    if (values[0] === values[1]) {
      return t_i18n('The values must be different.');
    }
    const newValue = values[valueOrder];
    if (!newValue.match(RELATIVE_DATE_REGEX) && !isValidDate(newValue)) {
      return t_i18n('', {
        id: 'The value must be a datetime or a relative date expressed in date math. See our documentation for more information.',
        values: {
          link: <Link target="_blank" to="https://docs.opencti.io/latest/reference/filters/?H=filters#operators">
            {t_i18n('our documentation')}
          </Link>,
        },
      });
    }
    return undefined;
  };
  const handleChangeRangeDateFilter = (value: string) => {
    const newValues = [...dateInput];
    newValues[valueOrder] = value;
    setDateInput(newValues);
    if (!generateErrorMessage(newValues)) {
      helpers?.handleReplaceFilterValues(
        filter?.id ?? '',
        newValues,
      );
    }
  };
  const handleChangeValue = (value: string) => {
    const newValues = [...dateInput];
    newValues[valueOrder] = value;
    setDateInput(newValues);
  };
  const handleChangeAbsoluteDateFilter = (value: Date | null) => {
    if (value) {
      handleChangeRangeDateFilter(value.toISOString());
    }
  };
  return (
    <div style={{ display: 'flex' }}>
      {isDatePickerOpen
        && <DateTimePicker
          open={true}
          onClose={() => setIsDatePickerOpen(false)}
          sx={{ display: 'none' }}
          onChange={handleChangeAbsoluteDateFilter}
           />
      }
      <TextField
        variant="outlined"
        size="small"
        fullWidth={true}
        id={filter?.id ?? `${filterKey}-id`}
        label={label}
        value={dateInput[valueOrder]}
        onChange={(event) => handleChangeValue(event.target.value)}
        autoFocus={true}
        onKeyDown={(event) => {
          if (event.key === 'Enter') {
            handleChangeRangeDateFilter((event.target as HTMLInputElement).value);
          }
        }}
        onBlur={(event) => {
          handleChangeRangeDateFilter(event.target.value);
        }}
        error={generateErrorMessage(dateInput) !== undefined}
        helperText={generateErrorMessage(dateInput)}
        InputProps={{
          endAdornment: <Button
            size="small"
            sx={{ marginLeft: -1, marginRight: -3, color: theme.palette.text.primary }}
            onClick={() => setIsDatePickerOpen(true)}
                        >
            <DateRangeOutlined/>
          </Button>,
        }}
      />
    </div>
  );
};

export default RelativeDateInput;
