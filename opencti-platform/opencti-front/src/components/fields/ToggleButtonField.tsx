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
  const { setFieldValue } = form;
  const { value, name } = field;
  return (
    <ToggleButtonGroup value={value} exclusive size="small">
      {items.map((item, index) => (
        <ToggleButton
          value={item.value}
          key={index}
          onClick={() => setFieldValue(name, (item.value === value) ? null : item.value)}
        >
          {item.content}
        </ToggleButton>))}
    </ToggleButtonGroup>

  );
};

export default ToggleButtonField;
