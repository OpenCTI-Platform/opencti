import React from 'react';
import { DatePicker as MuiDatePicker, DatePickerProps } from '@mui/x-date-pickers/DatePicker';
import { useTheme } from '@mui/material/styles';
import { useIntl } from 'react-intl';
import { Theme } from '../../Theme';
import { resolveDatePickerFormat } from '../../../utils/datePickerConfig';

const DatePicker: React.FC<DatePickerProps<Date>> = ({
  slotProps,
  format,
  ...datePickerProps
}) => {
  const theme = useTheme<Theme>();
  const { locale } = useIntl();
  const { value } = datePickerProps;
  const resolvedFormat = resolveDatePickerFormat(locale, format);

  return (
    <MuiDatePicker
      {...datePickerProps}
      format={resolvedFormat}
      slotProps={{
        ...slotProps,
        nextIconButton: {
          sx: {
            transform: theme.direction === 'rtl' ? 'rotate(180deg)' : 'none',
          },
        },
        previousIconButton: {
          sx: {
            transform: theme.direction === 'rtl' ? 'rotate(180deg)' : 'none',
          },
        },
        textField: {
          size: 'small',
          ...slotProps?.textField,
          sx: {
            '& .MuiOutlinedInput-root': {
              backgroundColor: theme.palette.background.secondary,
              '& fieldset': {
                borderColor: value
                  ? theme.palette.border.secondary
                  : 'transparent',
              },
              '&:hover fieldset, &.Mui-focused fieldset': {
                borderColor: theme.palette.border.secondary,
              },
            },
          },
        },
      }}
    />
  );
};

export default DatePicker;
