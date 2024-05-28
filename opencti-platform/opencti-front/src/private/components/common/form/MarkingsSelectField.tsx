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

type MarkingsSelectFieldValue = string[];

interface MarkingsSelectFieldInternalValue {
  [key: string]: string
}

interface MarkingsSelectFieldProps extends FieldProps<MarkingsSelectFieldValue> {
  markingDefinitions: EntityMarkingDefinition[]
  onChange?: (val: MarkingsSelectFieldValue) => void
}

const NOT_SHAREABLE_ID = 'not_shareable';

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

  const initialValues = markingTypes.reduce((acc, type) => ({
    ...acc,
    [type]: value.find((defId) => {
      const marking = markingDefinitions.find((def) => def.id === defId);
      return marking?.definition_type === type;
    }) ?? NOT_SHAREABLE_ID,
  }), {});

  const changeMarking = (type: string, markingId: string) => {
    const newValue = value.filter((defId) => {
      const marking = markingDefinitions.find((def) => def.id === defId);
      return marking?.definition_type !== type;
    });
    if (markingId !== NOT_SHAREABLE_ID) {
      newValue.push(markingId);
    }
    setFieldValue(name, newValue);
    onChange?.(newValue);
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
