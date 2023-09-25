import { FieldProps } from 'formik';
import FormControl from '@mui/material/FormControl';
import { ButtonGroup, FormLabel } from '@mui/material';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import Button from '@mui/material/Button';
import { useFormatter } from './i18n';

export type CheckboxesItem = {
  label: string
  value: string
};

type Props = FieldProps<CheckboxesItem[]> & {
  label: string
  items: CheckboxesItem[]
  maxHeight?: string
};

export default function CheckboxesField({
  form,
  field,
  label,
  items,
  maxHeight = '400px',
}: Props) {
  const { t } = useFormatter();

  const { setFieldValue } = form;
  const { name, value } = field;

  function isChecked(val: CheckboxesItem) {
    return value.includes(val);
  }

  function toggle(val: CheckboxesItem) {
    if (isChecked(val)) {
      setFieldValue(name, value.filter((v) => v !== val));
    } else {
      setFieldValue(name, [...value, val]);
    }
  }

  function checkAll() {
    setFieldValue(name, [...items]);
  }

  function checkNone() {
    setFieldValue(name, []);
  }

  return (
      <FormControl component="fieldset" name={name}>
        <FormLabel component="legend">{label}</FormLabel>

        <ButtonGroup size="small" sx={{ marginTop: '4px' }}>
          <Button
            variant={value.length === items.length ? 'contained' : undefined}
            onClick={checkAll}>
            {t('All')}
          </Button>
          <Button
            variant={value.length === 0 ? 'contained' : undefined}
            onClick={checkNone}>
            {t('None')}
          </Button>
        </ButtonGroup>

        <FormGroup sx={{
          maxHeight,
          flexWrap: 'nowrap',
          overflowY: 'auto',
        }}>
          {items.map((item) => (
            <FormControlLabel
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
}
