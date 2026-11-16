import React from 'react';
import { useTheme } from '@mui/material/styles';
import { PickersTextFieldProps } from '@mui/x-date-pickers/PickersTextField';
import { Theme } from '../../Theme';
import BaseDatePicker, { BaseDatePickerProps } from './picker/BaseDatePicker';

// Narrowed to the object form, so the wrapper can merge its own field props in.
type FieldDatePickerProps = Omit<BaseDatePickerProps, 'slotProps'> & {
  slotProps?: Omit<NonNullable<BaseDatePickerProps['slotProps']>, 'textField'> & {
    textField?: Partial<PickersTextFieldProps>;
  };
};

const DatePicker: React.FC<FieldDatePickerProps> = ({
  slotProps,
  ...datePickerProps
}) => {
  const theme = useTheme<Theme>();
  const { value } = datePickerProps;

  return (
    <BaseDatePicker
      {...datePickerProps}
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

export default DatePicker;
