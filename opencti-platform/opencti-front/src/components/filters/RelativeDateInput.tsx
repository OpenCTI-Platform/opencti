import React, { FunctionComponent, useState } from 'react';
import TextField from '@mui/material/TextField';
import { DateRangeOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import { useTheme } from '@mui/material/styles';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { useFormatter } from '../i18n';
import { BasicFilterInputProps } from './BasicFilterInput';
import { RELATIVE_DATE_REGEX } from '../../utils/filters/filtersUtils';
import { isValidDate } from '../../utils/String';

interface RelativeDateInputProps extends BasicFilterInputProps {
  valueOrder: number;
}

const RelativeDateInput: FunctionComponent<RelativeDateInputProps> = ({
  filter,
  filterKey,
  helpers,
  filterValues,
  label,
  type,
  valueOrder,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const [dateInput, setDateInput] = useState(filterValues);
  const [isDatePicker, setIsDatePicker] = useState(false);
  const [isDatePickerOpen, setIsDatePickerOpen] = useState(false);

  const generateErrorMessage = (values: string[]) => {
    if (values.length !== 2) {
      return t_i18n('The value must not be empty');
    }
    if (values.includes('')) {
      return t_i18n('The value must not be empty.');
    }
    const newValue = values[valueOrder];
    if (!newValue.match(RELATIVE_DATE_REGEX) && newValue !== 'now' && !isValidDate(newValue)) {
      return t_i18n('The value must be a datetime or a relative date in correct elastic format.');
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
  const handleChangeAbsoluteDateFilter = (value: Date | null) => {
    if (value) {
      handleChangeRangeDateFilter(value.toISOString());
    }
  };
  const handleChangeInputStyle = () => {
    setIsDatePicker(!isDatePicker);
    setIsDatePickerOpen(true);
  };
  return (
    <div style={{ display: 'flex' }}>
      {isDatePicker
        ? <DateTimePicker
            open={isDatePickerOpen}
            onClose={() => setIsDatePickerOpen(false)}
            onOpen={() => setIsDatePickerOpen(true)}
            sx={{ marginTop: 1 }}
            onChange={handleChangeAbsoluteDateFilter}
            value={new Date(filterValues[valueOrder])}
          />
        : <TextField
            variant="outlined"
            size="small"
            fullWidth={true}
            id={filter?.id ?? `${filterKey}-id`}
            label={label}
            type={type}
            defaultValue={filterValues[valueOrder]}
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
          />
      }
      <Button size="small" sx={{ width: '1%', color: theme.palette.text.primary }} onClick={handleChangeInputStyle}>
        <DateRangeOutlined/>
      </Button>
    </div>
  );
};

export default RelativeDateInput;
