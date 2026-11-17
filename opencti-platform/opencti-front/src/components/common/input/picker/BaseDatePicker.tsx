import React from 'react';
import { DatePicker as MuiDatePicker, DatePickerProps as MuiDatePickerProps } from '@mui/x-date-pickers/DatePicker';
import useFieldSectionSelection from '../../../../utils/hooks/useFieldSectionSelection';
import type { WithSectionSelection } from './pickerProps';

export type BaseDatePickerProps = WithSectionSelection<MuiDatePickerProps>;

/** The x-date-pickers `DatePicker`, unstyled, with the section selection of `useFieldSectionSelection`. */
const BaseDatePicker = ({ slotProps, ...props }: BaseDatePickerProps) => {
  const { fieldProps, ...sectionSelection } = useFieldSectionSelection(slotProps?.field?.onKeyDown);
  return (
    <MuiDatePicker
      {...props}
      {...sectionSelection}
      slotProps={{ ...slotProps, field: { ...slotProps?.field, ...fieldProps } }}
    />
  );
};

export default BaseDatePicker;
