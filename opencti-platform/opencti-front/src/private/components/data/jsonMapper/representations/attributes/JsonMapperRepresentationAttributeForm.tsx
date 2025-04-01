import React, { FunctionComponent, useEffect, useState } from 'react';
import JsonMapperRepresentationAttributeOptions from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributeOptions';
import { alphabet } from '@components/data/jsonMapper/representations/attributes/AttributeUtils';
import makeStyles from '@mui/styles/makeStyles';
import { Field, FieldProps } from 'formik';
import JsonMapperRepresentationDialogOption from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationDialogOption';
import JsonMapperRepresentationAttributeSelectedConfigurations
  from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributeSelectedConfigurations';
import { JsonMapperRepresentationAttributeFormData } from '@components/data/jsonMapper/representations/attributes/Attribute';
import { SchemaAttribute } from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributesForm';
import { useFormatter } from '../../../../../../components/i18n';
import { isEmptyField } from '../../../../../../utils/utils';
import TextField from '../../../../../../components/TextField';

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
  inputError: {
    '& fieldset': {
      borderColor: 'rgb(244, 67, 54)',
    },
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
  const { setFieldValue } = form;

  const options = alphabet(26);

  // -- ERRORS --

  const hasErrors = () => {
    const missMandatoryValue = schemaAttribute.mandatory && isEmptyField(value?.column_name);
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

  const onColumnChange = async (column: string | null) => {
    if (!value) {
      // this attribute was not set yet, initialize
      const newAttribute: JsonMapperRepresentationAttributeFormData = {
        key: schemaAttribute.name,
        column_name: column ?? undefined,
      };
      await setFieldValue(name, newAttribute);
    } else {
      const updateAttribute: JsonMapperRepresentationAttributeFormData = {
        ...value,
        column_name: column ?? undefined,
      };
      await setFieldValue(name, updateAttribute);
    }
  };

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
          name="path"
          label={t_i18n('JSON Path')}
          fullWidth={true}
        />

        {/** <MUIAutocomplete
          selectOnFocus
          openOnFocus
          autoSelect={false}
          autoHighlight
          options={options}
          // attribute might be unselected yet, but we need value=null as this is a controlled component
          value={value?.column_name ?? null}
          onChange={(_, val) => onColumnChange(val)}
          renderInput={(params) => (
            <MuiTextField
              {...params}
              label={t_i18n('Column index')}
              variant="outlined"
              size="small"
            />
          )}
          className={classNames({
            [classes.inputError]: errors,
          })}
        />* */}
      </div>
      <div>
        {
          (schemaAttribute.type === 'date' || schemaAttribute.multiple || schemaAttribute.editDefault)
            && <JsonMapperRepresentationDialogOption configuration={value}>
              <JsonMapperRepresentationAttributeOptions
                schemaAttribute={schemaAttribute}
                attributeName={name}
                form={form}
              />
            </JsonMapperRepresentationDialogOption>
        }
      </div>
      <JsonMapperRepresentationAttributeSelectedConfigurations
        configuration={value}
      />
    </div>
  );
};

export default JsonMapperRepresentationAttributeForm;
