import React, { FunctionComponent, useState } from 'react';
import TextField from '@mui/material/TextField';
import { ClearOutlined, DateRangeOutlined } from '@mui/icons-material';
import { IconButton } from '@filigran/design-system';
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
  /** Only ONE field in the popover may claim focus. */
  autoFocus?: boolean;
}

const RelativeDateInput: FunctionComponent<RelativeDateInputProps> = ({
  filter,
  filterKey,
  helpers,
  label,
  valueOrder,
  dateInput,
  setDateInput,
  autoFocus = false,
}) => {
  const { t_i18n } = useFormatter();
  const [isDatePickerOpen, setIsDatePickerOpen] = useState(false);

  const generateErrorMessage = (values: string[]) => {
    const newValue = values[valueOrder];
    if (!newValue) {
      return t_i18n('The value must not be empty');
    }
    if (values[0] === values[1]) {
      return t_i18n('The values must be different.');
    }
    if (!RELATIVE_DATE_REGEX.test(newValue) && !isValidDate(newValue)) {
      return t_i18n('', {
        id: 'The value must be a datetime or a relative date expressed in date math. See our documentation for more information.',
        values: {
          link: (
            <Link target="_blank" to="https://docs.opencti.io/latest/reference/filters/?H=filters#operators">
              {t_i18n('our documentation')}
            </Link>
          ),
        },
      });
    }
    return undefined;
  };
  const isValuesIntervalValid = (values: string[]) => {
    const isValidString = values.every((v) => RELATIVE_DATE_REGEX.test(v) || isValidDate(v));
    if (values.length === 2 && values[0] !== values[1] && isValidString) {
      return true;
    }
    return false;
  };
  const handleChangeRangeDateFilter = (value: string) => {
    const newValues = [...dateInput];
    newValues[valueOrder] = value;
    setDateInput(newValues);
    if (isValuesIntervalValid(newValues)) {
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
  const handleClear = () => {
    handleChangeValue('');
  };
  return (
    <div style={{ display: 'flex' }}>
      {isDatePickerOpen
        && (
          <DateTimePicker
            open={true}
            onClose={() => setIsDatePickerOpen(false)}
            sx={{ display: 'none' }}
            onChange={handleChangeAbsoluteDateFilter}
          />
        )
      }
      <TextField
        variant="outlined"
        size="small"
        fullWidth={true}
        id={filter?.id ?? `${filterKey}-id`}
        label={label}
        value={dateInput[valueOrder]}
        onChange={(event) => handleChangeValue(event.target.value)}
        autoFocus={autoFocus}
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
        slotProps={{
          input: {
            endAdornment: (
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                {dateInput[valueOrder] && (
                  <IconButton
                    variant="default"
                    priority="tertiary"
                    size="sm"
                    onClick={handleClear}
                    aria-label="clear"
                    icon={<ClearOutlined fontSize="small" />}
                  />
                )}
                <IconButton
                  variant="default"
                  priority="tertiary"
                  size="sm"
                  onClick={() => setIsDatePickerOpen(true)}
                  aria-label="open date picker"
                  icon={<DateRangeOutlined fontSize="small" />}
                />
              </span>
            ),
          },
        }}
      />
    </div>
  );
};

export default RelativeDateInput;
