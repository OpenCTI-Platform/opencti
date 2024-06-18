import { FieldProps } from 'formik';
import React, { ReactNode } from 'react';
import { FormLabel, ToggleButton, ToggleButtonGroup } from '@mui/material';
import FormControl from '@mui/material/FormControl';
import { useFormatter } from '../i18n';

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
  const { t_i18n } = useFormatter();
  const { setFieldValue } = form;
  const { value, name } = field;
  return (
    <FormControl>
      <FormLabel>{t_i18n('Default value')}</FormLabel>
      <ToggleButtonGroup value={value} exclusive size="small" sx={{ paddingTop: 1 }}>
        {items.map((item, index) => (
          <ToggleButton
            value={item.value}
            key={index}
            onClick={() => setFieldValue(name, (item.value === value) ? null : item.value)}
          >
            {item.content}
          </ToggleButton>))}
      </ToggleButtonGroup>
    </FormControl>
  );
};

export default ToggleButtonField;
