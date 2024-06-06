import { FieldProps } from 'formik';
import React, { ReactNode } from 'react';
import { ToggleButton, ToggleButtonGroup } from '@mui/material';

interface ToggleButtonFieldProps extends FieldProps<boolean> {
  items: Item[]
}

interface Item {
  value: boolean
  content: ReactNode
}

const ToggleButtonField = ({
  form,
  field,
  items,
}: ToggleButtonFieldProps) => {
  return (
    <ToggleButtonGroup size="small" aria-label="Small sizes">
      {items.map((item, index) => <ToggleButton value={item.value} key={index}>
        {item.content}
      </ToggleButton>)}

    </ToggleButtonGroup>

  );
};

export default ToggleButtonField;
