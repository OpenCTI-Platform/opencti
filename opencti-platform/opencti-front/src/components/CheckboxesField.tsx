import React from 'react';
import { FieldProps } from 'formik';
import FormControl from '@mui/material/FormControl';
import { ButtonGroup, FormLabel } from '@mui/material';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import Button from '@common/button/Button';
import { useFormatter } from './i18n';
import { FieldOption } from '../utils/field';

type CheckboxesFieldProps = FieldProps<FieldOption[]> & {
  label: string;
  items: FieldOption[];
};

const CheckboxesField = ({
  form,
  field,
  label,
  items,
}: CheckboxesFieldProps) => {
  const { t_i18n } = useFormatter();

  const { setFieldValue } = form;
  const { name, value } = field;

  const isChecked = (val: FieldOption) => value.includes(val);

  const toggle = (val: FieldOption) => {
    if (isChecked(val)) {
      setFieldValue(name, value.filter((v) => v !== val));
    } else {
      setFieldValue(name, [...value, val]);
    }
  };

  const checkAll = () => setFieldValue(name, [...items]);

  const checkNone = () => setFieldValue(name, []);

  return (
    <FormControl component="fieldset" name={name}>
      <FormLabel component="legend">{label}</FormLabel>

      <ButtonGroup size="small" sx={{ marginTop: '4px' }}>
        <Button
          disabled={items.length === 0}
          variant={(items.length > 0 && value.length === items.length) ? 'primary' : 'tertiary'}
          onClick={checkAll}
        >
          {t_i18n('All')}
        </Button>
        <Button
          disabled={items.length === 0}
          variant={(items.length > 0 && value.length === 0) ? 'primary' : 'tertiary'}
          onClick={checkNone}
        >
          {t_i18n('None')}
        </Button>
      </ButtonGroup>

      <FormGroup sx={{
        maxHeight: '300px',
        flexWrap: 'nowrap',
        overflowY: 'auto',
      }}
      >
        {items.map((item) => (
          <FormControlLabel
            key={item.label}
            label={item.label}
            control={(
              <Checkbox
                checked={isChecked(item)}
                name={item.value}
                onChange={() => toggle(item)}
              />
            )}
          />
        ))}
      </FormGroup>
    </FormControl>
  );
};

export default CheckboxesField;
