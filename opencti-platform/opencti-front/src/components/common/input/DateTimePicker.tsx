import React from 'react';
import { DateTimePicker as MuiDateTimePicker, DateTimePickerProps } from '@mui/x-date-pickers/DateTimePicker';
import { useTheme } from '@mui/material/styles';
import { TextFieldProps } from '@mui/material/TextField';
import { Theme } from '../../Theme';

// The field renders a MUI TextField (enableAccessibleFieldDOMStructure is false),
// so its slot props are TextField props rather than the v8 PickersTextField union.
type FieldDateTimePickerProps = Omit<DateTimePickerProps<false>, 'slotProps'> & {
  slotProps?: Omit<NonNullable<DateTimePickerProps<false>['slotProps']>, 'textField'> & {
    textField?: Partial<TextFieldProps>;
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
      enableAccessibleFieldDOMStructure={false}
      {...dateTimePickerProps}
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

export default DateTimePicker;
