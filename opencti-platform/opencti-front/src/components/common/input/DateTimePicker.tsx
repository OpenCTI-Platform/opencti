import React from 'react';
import { DateTimePicker as MuiDateTimePicker, DateTimePickerProps } from '@mui/x-date-pickers/DateTimePicker';
import { useTheme } from '@mui/material/styles';
import { PickersTextFieldProps } from '@mui/x-date-pickers/PickersTextField';
import { Theme } from '../../Theme';

// Narrowed to the object form, so the wrapper can merge its own field props in.
type FieldDateTimePickerProps = Omit<DateTimePickerProps, 'slotProps'> & {
  slotProps?: Omit<NonNullable<DateTimePickerProps['slotProps']>, 'textField'> & {
    textField?: Partial<PickersTextFieldProps>;
  };
};

const DateTimePicker: React.FC<FieldDateTimePickerProps> = ({
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
            '& .MuiPickersOutlinedInput-root': {
              // background comes from the theme's MuiPickersOutlinedInput override,
              // which paints every outlined field with the library input token.
              '& fieldset': {
                borderColor: value ? theme.palette.border.secondary : 'transparent',
              },
              // The outline class outranks the picker's own focused rule
              // (`.Mui-focused:not(.Mui-error) .MuiPickersOutlinedInput-notchedOutline`).
              '&:hover fieldset.MuiPickersOutlinedInput-notchedOutline, &.Mui-focused fieldset.MuiPickersOutlinedInput-notchedOutline': {
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
