import React, { FunctionComponent } from 'react';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
import { useFormatter } from '../../../components/i18n';
import type { WidgetColumn } from '../../../utils/widget/widget';
import TextField from '../../../components/TextField';

interface WidgetCreationAttributesProps {
  value: readonly WidgetColumn[],
  i: number,
  onChange: (i: number,
    value: WidgetColumn[],
  ) => void,
}

const WidgetAttributesInput: FunctionComponent<WidgetCreationAttributesProps> = ({
  value,
  i,
  onChange,
}) => {
  const { t_i18n } = useFormatter();
  const availableColumns: WidgetColumn[] = [
    { attribute: 'name', label: 'Name' },
    { attribute: 'entity_type', label: 'Entity type' },
    { attribute: 'relationship_type', label: 'Relationship type' },
    { attribute: 'created_at', label: 'Creation date' },
    { attribute: 'createdBy.name', label: 'Author' },
    { attribute: 'objectMarking.definition', label: 'Marking' },
  ];
  const attributesValidation = () => Yup.object().shape({
    variableName: Yup.string()
      .test('no-space', 'This field cannot contain spaces', (v) => {
        return !v?.includes(' ');
      })
      .required(t_i18n('This field is required')),
  });
  const setFieldValue = (attribute: string | null, field: string, newValue: string) => {
    const newColumns = value.map((c) => (c.attribute === attribute ? {
      ...c,
      [field]: newValue,
    } : c));
    onChange(i, newColumns);
  };
  return (
    <FormControl
      fullWidth={true}
      style={{
        flex: 1,
        marginRight: 20,
        width: '100%',
      }}
    >
      <InputLabel>{t_i18n('Attributes')}</InputLabel>
      <Select
        fullWidth={true}
        multiple={true}
        value={value}
        onChange={(event) => onChange(
          i,
          event.target.value,
        )
        }
      >
        {availableColumns.map((v) => (
          <MenuItem
            key={v.attribute}
            value={v}
          >
            {t_i18n(v.label)}
          </MenuItem>
        ))}
      </Select>
      {value.map((column) => (
        <Formik
          key={column.attribute}
          initialValues={{
            variableName: column.variableName ?? column.attribute,
            label: column.label ?? '',
            attribute: column.attribute,
          }}
          validationSchema={attributesValidation()}
          onSubmit={() => {}}
        >
          {({ isValid }) => (
            <Form>
              <Field
                component={TextField}
                name="attribute"
                label={t_i18n('Attribute')}
                disabled={true}
                style={{ marginTop: 20, marginLeft: 30, width: 220 }}
              />
              <Field
                component={TextField}
                name="label"
                label={t_i18n('Label')}
                style={{ marginTop: 20, marginLeft: 10, width: 220 }}
                onChange={isValid ? (n: string, v: string) => setFieldValue(column.attribute, n, v) : undefined}
              />
              <Field
                component={TextField}
                name="variableName"
                label={t_i18n('Variable name')}
                style={{ marginTop: 20, marginLeft: 10, width: 220 }}
                onChange={isValid ? (n: string, v: string) => setFieldValue(column.attribute, n, v) : undefined}
              />
            </Form>
          )}
        </Formik>))
      }
    </FormControl>
  );
};

export default WidgetAttributesInput;
