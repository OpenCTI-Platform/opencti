import React, { FunctionComponent } from 'react';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import * as Yup from 'yup';
import { Field, FieldArray, Form, Formik } from 'formik';
import IconButton from '@mui/material/IconButton';
import { DeleteOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import type { WidgetColumn } from '../../../utils/widget/widget';
import TextField from '../../../components/TextField';

interface WidgetCreationAttributesProps {
  value: readonly WidgetColumn[],
  onChange: (value: WidgetColumn[]) => void,
}

const WidgetAttributesInput: FunctionComponent<WidgetCreationAttributesProps> = ({
  value,
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
  const attributesValidation = () => Yup.object({
    attributes: Yup.array().of(
      Yup.object().shape({
        variableName: Yup.string()
          .test('no-space', 'This field cannot contain spaces', (v) => {
            return !v?.includes(' ');
          })
          .required(t_i18n('This field is required')),
      }),
    ),
  });
  const setFieldValue = (attribute: string | null, field: string, newValue: string) => {
    const newColumns = value.map((c) => (c.attribute === attribute ? {
      ...c,
      [field]: newValue,
    } : c));
    onChange(newColumns);
  };
  const removeAttribute = (attribute: string | null) => {
    const newColumns = value.filter((c) => c.attribute !== attribute);
    onChange(newColumns);
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
        onChange={(event) => onChange(event.target.value)
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
      <Formik<{ attributes: WidgetColumn[] }>
        initialValues={{
          attributes: value.map((column) => ({
            variableName: column.variableName ?? column.attribute,
            label: column.label ?? '',
            attribute: column.attribute,
          })),
        }}
        validationSchema={attributesValidation()}
        onSubmit={() => {}}
      >
        {({ isValid }) => (
          <Form>
            <FieldArray name={'attributes'}>
              {() => (
                <>
                  {value.map((row, _) => (
                    <>
                      <Field
                        component={TextField}
                        name="attribute"
                        label={t_i18n('Attribute')}
                        disabled={true}
                        value={row.attribute}
                        style={{ marginTop: 20, marginLeft: 30, width: 220 }}
                      />
                      <Field
                        component={TextField}
                        name="label"
                        label={t_i18n('Label')}
                        value={row.label}
                        style={{ marginTop: 20, marginLeft: 10, width: 220 }}
                        onChange={isValid ? (n: string, v: string) => setFieldValue(row.attribute, n, v) : undefined}
                      />
                      <Field
                        component={TextField}
                        name="variableName"
                        label={t_i18n('Variable name')}
                        value={row.variableName}
                        style={{ marginTop: 20, marginLeft: 10, width: 220 }}
                        onChange={isValid ? (n: string, v: string) => setFieldValue(row.attribute, n, v) : undefined}
                      />
                      <IconButton
                        size="small"
                        color="primary"
                        style={{ marginTop: 30 }}
                        onClick={() => removeAttribute(row.attribute)}
                      >
                        <DeleteOutlined fontSize="small" />
                      </IconButton>
                    </>
                  ))}
                </>
              )}
            </FieldArray>
          </Form>
        )}
      </Formik>
    </FormControl>
  );
};

export default WidgetAttributesInput;
