import { Fragment, FunctionComponent, useContext } from 'react';
import Divider from '@mui/material/Divider';
import FormHelperText from '@mui/material/FormHelperText';
import { getIn, useFormikContext } from 'formik';
import { CustomFieldDef, CustomFieldFormValues, getCustomFieldSetting } from '../../../../utils/customFields';
import { CustomFieldInput } from './CustomFieldsInput';
import { CustomFieldsCreationContext } from './CustomFieldsFormik';

interface CustomFieldValuesCreationProps {
  entityType?: string;
  definitions?: readonly CustomFieldDef[];
}

// Definitions are shared with the parent form's defaults, validation and creation serialization.
const CustomFieldValuesCreation: FunctionComponent<CustomFieldValuesCreationProps> = (props) => {
  const context = useContext(CustomFieldsCreationContext);
  const entityType = props.entityType ?? context.entityType;
  const definitions = props.definitions ?? context.definitions;
  const { values, errors, touched, submitCount, setFieldValue, setFieldTouched } = useFormikContext<{ customFields: CustomFieldFormValues }>();

  if (definitions.length === 0) return null;

  return (
    <>
      <Divider style={{ marginTop: 20 }} />
      {definitions.map((definition) => {
        const name = `customFields.${definition.id}`;
        const error = (submitCount > 0 || getIn(touched, name)) ? getIn(errors, name) : undefined;
        return (
          <Fragment key={definition.id}>
            <CustomFieldInput
              definition={definition}
              mandatory={getCustomFieldSetting(definition, entityType)?.mandatory ?? false}
              value={values.customFields?.[definition.id] ?? ''}
              onChange={(value) => {
                setFieldTouched(name, true, false);
                setFieldValue(name, value);
              }}
            />
            {typeof error === 'string' && <FormHelperText error role="alert">{error}</FormHelperText>}
          </Fragment>
        );
      })}
    </>
  );
};

export default CustomFieldValuesCreation;
