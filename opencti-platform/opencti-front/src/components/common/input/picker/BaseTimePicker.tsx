import React from 'react';
import { TimePicker as MuiTimePicker, TimePickerProps as MuiTimePickerProps } from '@mui/x-date-pickers/TimePicker';
import useFieldSectionSelection from '../../../../utils/hooks/useFieldSectionSelection';
import type { WithSectionSelection } from './pickerProps';

export type BaseTimePickerProps = WithSectionSelection<MuiTimePickerProps>;

/** The x-date-pickers `TimePicker`, unstyled, with the section selection of `useFieldSectionSelection`. */
const BaseTimePicker = ({ slotProps, ...props }: BaseTimePickerProps) => {
  const { fieldRef, ...sectionSelection } = useFieldSectionSelection();
  return (
    <MuiTimePicker
      {...props}
      {...sectionSelection}
      slotProps={{ ...slotProps, field: { ...slotProps?.field, fieldRef } }}
    />
  );
};

export default BaseTimePicker;
