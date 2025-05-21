import React, { FunctionComponent, useEffect, useState } from 'react';
import JsonMapperRepresentationAttributeOptions from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributeOptions';
import makeStyles from '@mui/styles/makeStyles';
import { Field, FieldProps } from 'formik';
import JsonMapperRepresentationDialogOption from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationDialogOption';
import { JsonMapperRepresentationAttributeFormData } from '@components/data/jsonMapper/representations/attributes/Attribute';
import { SchemaAttribute } from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributesForm';
import { useFormatter } from '../../../../../../components/i18n';
import { isEmptyField } from '../../../../../../utils/utils';
import TextField from '../../../../../../components/TextField';
import JsonMapperRepresentionAttributeSelectedConfigurations from './JsonMapperRepresentionAttributeSelectedConfigurations';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    width: '100%',
    display: 'inline-grid',
    gridTemplateColumns: '2fr 3fr 50px',
    alignItems: 'center',
    marginTop: '10px',
    gap: '10px',
  },
  redStar: {
    color: 'rgb(244, 67, 54)',
    marginLeft: '5px',
  },
}));

export type RepresentationAttributeForm = JsonMapperRepresentationAttributeFormData | undefined;

interface JsonMapperRepresentationAttributeFormProps
  extends FieldProps<RepresentationAttributeForm> {
  schemaAttribute: SchemaAttribute;
  label: string;
  handleErrors: (key: string, value: string | null) => void;
}

const JsonMapperRepresentationAttributeForm: FunctionComponent<
JsonMapperRepresentationAttributeFormProps
> = ({ form, field, schemaAttribute, label, handleErrors }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const { name, value } = field;

  // -- ERRORS --

  const hasErrors = () => {
    const missMandatoryValue = schemaAttribute.mandatory && isEmptyField(value?.attr_path?.path);
    const missSettingsDefaultValue = isEmptyField(schemaAttribute.defaultValues);
    const missDefaultValue = isEmptyField(value?.default_values);
    return missMandatoryValue && missSettingsDefaultValue && missDefaultValue;
  };

  const [errors, setErrors] = useState(hasErrors());

  // -- EVENTS --

  useEffect(() => {
    setErrors(hasErrors());
  }, [value, schemaAttribute]);

  useEffect(() => {
    if (errors) {
      handleErrors(schemaAttribute.name, 'This attribute is required');
    } else {
      handleErrors(schemaAttribute.name, null);
    }
  }, [errors]);

  return (
    <div className={classes.container}>
      <div>
        {label}
        {schemaAttribute.mandatory && <span className={classes.redStar}>*</span>}
      </div>
      {/** <div>
        <Field
          name="newAccessRight"
          label={t_i18n('Mode')}
          component={SelectField}
          inputProps={{ 'aria-label': 'Without label' }}
          disableUnderline
          InputLabelProps={{ sx: visuallyHidden }}
          style={{ m: 1, minWidth: 100 }}
          value={value?.column_name ?? 'simple'}
          size="small"
        >
          <MenuItem value="simple">{t_i18n('Simple')}</MenuItem>
          <MenuItem value="complex">{t_i18n('Complex')}</MenuItem>
        </Field>
      </div>* */}
      <div>
        <Field
          component={TextField}
          variant="standard"
          name={`${name}.attr_path.path`}
          // value={value?.attr_path?.path ?? ''}
          // onChange={(_: unknown, val: string) => onPathChange(val)}
          label={t_i18n('JSON Path')}
          fullWidth={true}
        />
      </div>
      <div>
        {
          (schemaAttribute.type === 'date' || schemaAttribute.multiple || schemaAttribute.editDefault)
            && <JsonMapperRepresentationDialogOption configuration={value}>
              <JsonMapperRepresentationAttributeOptions
                schemaAttribute={schemaAttribute}
                baseAttributeName={name}
                configurationAttributeName={`${name}.attr_path.configuration`}
                form={form}
              />
            </JsonMapperRepresentationDialogOption>
        }
      </div>
      <JsonMapperRepresentionAttributeSelectedConfigurations configuration={value?.attr_path?.configuration}/>
    </div>
  );
};

export default JsonMapperRepresentationAttributeForm;
