import React from 'react';
import { DateTimePicker as MuiDateTimePicker, DateTimePickerProps } from '@mui/x-date-pickers/DateTimePicker';
import { useTheme } from '@mui/material/styles';
import { Theme } from '../../Theme';

const DateTimePicker: React.FC<DateTimePickerProps<Date>> = ({
  slotProps,
  ...dateTimePickerProps
}) => {
  const theme = useTheme<Theme>();
  const { value } = dateTimePickerProps;

  return (
    <MuiDateTimePicker
      {...dateTimePickerProps}
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

export default DateTimePicker;
