import React from 'react';
import { DateTimePicker as MuiDateTimePicker, DateTimePickerProps as MuiDateTimePickerProps } from '@mui/x-date-pickers/DateTimePicker';
import useFieldSectionSelection from '../../../../utils/hooks/useFieldSectionSelection';
import type { WithSectionSelection } from './pickerProps';

export type BaseDateTimePickerProps = WithSectionSelection<MuiDateTimePickerProps>;

/** The x-date-pickers `DateTimePicker`, unstyled, with the section selection of `useFieldSectionSelection`. */
const BaseDateTimePicker = ({ slotProps, ...props }: BaseDateTimePickerProps) => {
  const { fieldProps, ...sectionSelection } = useFieldSectionSelection(slotProps?.field?.onKeyDown);
  return (
    <MuiDateTimePicker
      {...props}
      {...sectionSelection}
      slotProps={{ ...slotProps, field: { ...slotProps?.field, ...fieldProps } }}
    />
  );
};

export default BaseDateTimePicker;
