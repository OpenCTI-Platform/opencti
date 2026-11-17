import React from 'react';
import { TimePicker as MuiTimePicker, TimePickerProps as MuiTimePickerProps } from '@mui/x-date-pickers/TimePicker';
import useFieldSectionSelection from '../../../../utils/hooks/useFieldSectionSelection';
import type { WithSectionSelection } from './pickerProps';

export type BaseTimePickerProps = WithSectionSelection<MuiTimePickerProps>;

/** The x-date-pickers `TimePicker`, unstyled, with the section selection of `useFieldSectionSelection`. */
const BaseTimePicker = ({ slotProps, ...props }: BaseTimePickerProps) => {
  const { fieldProps, ...sectionSelection } = useFieldSectionSelection(slotProps?.field?.onKeyDown);
  return (
    <MuiTimePicker
      {...props}
      {...sectionSelection}
      slotProps={{ ...slotProps, field: { ...slotProps?.field, ...fieldProps } }}
    />
  );
};

export default BaseTimePicker;
