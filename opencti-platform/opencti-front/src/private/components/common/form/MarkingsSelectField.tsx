import { Field, FieldProps, Formik } from 'formik';
import React from 'react';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/fields/SelectField';

export type EntityMarkingDefinition = {
  id: string
  definition: string
  definition_type: string
  x_opencti_order: number
};

type MarkingsSelectFieldValue = EntityMarkingDefinition[];

interface MarkingsSelectFieldInternalValue {
  [key: string]: string
}

interface MarkingsSelectFieldProps extends FieldProps<MarkingsSelectFieldValue> {
  markingDefinitions: EntityMarkingDefinition[]
  onChange?: (type: string, val: string) => void
}

const ALL_ID = 'all';
const NOT_SHAREABLE_ID = 'none';

const MarkingsSelectField = ({
  form,
  field,
  markingDefinitions,
  onChange,
}: MarkingsSelectFieldProps) => {
  const { t_i18n } = useFormatter();
  const { setFieldValue } = form;
  const { value, name } = field;

  const markingTypes = Array.from(new Set(
    markingDefinitions.map((m) => m.definition_type),
  ));
  const initialValues: Record<string, string> = {};
  markingTypes.forEach((type) => {
    if (!value.find((v) => v.definition_type === type)) {
      initialValues[type] = ALL_ID;
    } else if (value.find((v) => v.definition_type === type && v.id === 'none')) {
      initialValues[type] = NOT_SHAREABLE_ID;
    } else {
      const val = value.find((v) => v.definition_type === type);
      if (val) {
        initialValues[type] = val.id;
      }
    }
  });

  const changeMarking = (type: string, markingId: string) => {
    const newValue = [...Object.entries(initialValues).filter(([definition_type]) => definition_type !== type).map(([_, v]) => v), { id: markingId, definition_type: type }];
    setFieldValue(name, newValue);
    onChange?.(type, markingId);
  };

  return (
    <Formik<MarkingsSelectFieldInternalValue>
      initialValues={initialValues}
      onSubmit={() => {}}
    >
      {() => (
        markingTypes.map((type, i) => (
          <Field
            key={type}
            name={type}
            label={type}
            fullWidth={true}
            variant="standard"
            containerstyle={{ marginTop: i > 0 ? 20 : 5, width: '100%' }}
            component={SelectField}
            onChange={changeMarking}
            displ
          >
            <MenuItem value={ALL_ID} key={ALL_ID}>
              {t_i18n('No restrictions')}
            </MenuItem>
            <MenuItem value={NOT_SHAREABLE_ID} key={NOT_SHAREABLE_ID}>
              {t_i18n('Not shareable')}
            </MenuItem>
            {markingDefinitions
              .filter((def) => def.definition_type === type)
              .sort((defA, defB) => defA.x_opencti_order - defB.x_opencti_order)
              .map((def) => (
                <MenuItem value={def.id} key={def.id}>
                  {def.definition}
                </MenuItem>
              ))}
          </Field>
        ))
      )}
    </Formik>
  );
};

export default MarkingsSelectField;
