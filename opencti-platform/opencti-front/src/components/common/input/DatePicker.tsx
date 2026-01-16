import React from 'react';
import { DatePicker as MuiDatePicker, DatePickerProps } from '@mui/x-date-pickers/DatePicker';
import { useTheme } from '@mui/material/styles';
import { Theme } from '../../Theme';

const DatePicker: React.FC<DatePickerProps<Date>> = ({
  slotProps,
  ...datePickerProps
}) => {
  const theme = useTheme<Theme>();
  const { value } = datePickerProps;

  return (
    <MuiDatePicker
      {...datePickerProps}
      slotProps={{
        ...slotProps,
        textField: {
          variant: 'outlined',
          size: 'small',
          ...slotProps?.textField,
          sx: {
            '& .MuiOutlinedInput-root': {
              backgroundColor: theme.palette.background.secondary,
              '& fieldset': {
                borderColor: value ? theme.palette.border.secondary : 'transparent',
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
