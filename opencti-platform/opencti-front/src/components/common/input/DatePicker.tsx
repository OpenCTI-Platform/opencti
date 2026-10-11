import React from 'react';
import { DatePicker as MuiDatePicker, DatePickerProps } from '@mui/x-date-pickers/DatePicker';
import { useTheme } from '@mui/material/styles';
import { TextFieldProps } from '@mui/material/TextField';
import { Theme } from '../../Theme';

// The field renders a MUI TextField (enableAccessibleFieldDOMStructure is false),
// so its slot props are TextField props rather than the v8 PickersTextField union.
type FieldDatePickerProps = Omit<DatePickerProps<false>, 'slotProps'> & {
  slotProps?: Omit<NonNullable<DatePickerProps<false>['slotProps']>, 'textField'> & {
    textField?: Partial<TextFieldProps>;
  };
};

const DatePicker: React.FC<FieldDatePickerProps> = ({
  slotProps,
  ...datePickerProps
}) => {
  const theme = useTheme<Theme>();
  const { value } = datePickerProps;

  return (
    <MuiDatePicker
      enableAccessibleFieldDOMStructure={false}
      {...datePickerProps}
      slotProps={{
        ...slotProps,
        textField: {
          variant: 'outlined',
          size: 'small',
          ...slotProps?.textField,
          sx: {
            '& .MuiOutlinedInput-root': {
              // background comes from the theme's MuiOutlinedInput override,
              // which paints every outlined field with the library input token.
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
