import React, { FunctionComponent, useEffect, useState } from 'react';
import MUIAutocomplete from '@mui/material/Autocomplete';
import MuiTextField from '@mui/material/TextField';
import classNames from 'classnames';
import CsvMapperRepresentationAttributeOptions from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributeOptions';
import { alphabet } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import makeStyles from '@mui/styles/makeStyles';
import { FieldProps } from 'formik';
import CsvMapperRepresentationDialogOption from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationDialogOption';
import CsvMapperRepresentionAttributeSelectedConfigurations from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentionAttributeSelectedConfigurations';
import { CsvMapperRepresentationAttributeFormData } from '@components/data/csvMapper/representations/attributes/Attribute';
import { SchemaAttribute } from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributesForm';
import { useFormatter } from '../../../../../../components/i18n';
import { isEmptyField } from '../../../../../../utils/utils';

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

export type RepresentationAttributeForm = CsvMapperRepresentationAttributeFormData | undefined;

interface CsvMapperRepresentationAttributeFormProps
  extends FieldProps<RepresentationAttributeForm> {
  schemaAttribute: SchemaAttribute;
  label: string;
  handleErrors: (key: string, value: string | null) => void;
}

const CsvMapperRepresentationAttributeForm: FunctionComponent<
CsvMapperRepresentationAttributeFormProps
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
      const newAttribute: CsvMapperRepresentationAttributeFormData = {
        key: schemaAttribute.name,
        column_name: column ?? undefined,
      };
      await setFieldValue(name, newAttribute);
    } else {
      const updateAttribute: CsvMapperRepresentationAttributeFormData = {
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
      <div>
        <MUIAutocomplete
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
        />
      </div>
      <div>
        {
          (schemaAttribute.type === 'date' || schemaAttribute.multiple || schemaAttribute.editDefault)
            && <CsvMapperRepresentationDialogOption configuration={value}>
              <CsvMapperRepresentationAttributeOptions
                schemaAttribute={schemaAttribute}
                attributeName={name}
                form={form}
              />
            </CsvMapperRepresentationDialogOption>
        }
      </div>
      <CsvMapperRepresentionAttributeSelectedConfigurations
        configuration={value}
      />
    </div>
  );
};

export default CsvMapperRepresentationAttributeForm;
