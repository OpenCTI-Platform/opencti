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

type CheckboxesFieldProps = FieldProps<CheckboxesItem[]> & {
  label: string
  items: CheckboxesItem[]
  maxHeight?: string
};

const CheckboxesField = ({
  form,
  field,
  label,
  items,
  maxHeight = '300px',
}: CheckboxesFieldProps) => {
  const { t } = useFormatter();

  const { setFieldValue } = form;
  const { name, value } = field;

  const isChecked = (val: CheckboxesItem) => value.includes(val);

  const toggle = (val: CheckboxesItem) => {
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
            variant={(items.length > 0 && value.length === items.length) ? 'contained' : undefined}
            onClick={checkAll}>
            {t('All')}
          </Button>
          <Button
            disabled={items.length === 0}
            variant={(items.length > 0 && value.length === 0) ? 'contained' : undefined}
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
