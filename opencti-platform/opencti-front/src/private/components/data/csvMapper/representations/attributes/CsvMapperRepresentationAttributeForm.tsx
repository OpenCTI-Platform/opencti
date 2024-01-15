import React, { FunctionComponent, useEffect, useState } from 'react';
import MUIAutocomplete from '@mui/material/Autocomplete';
import MuiTextField from '@mui/material/TextField';
import classNames from 'classnames';
import CsvMapperRepresentationAttributeOptions from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributeOptions';
import { alphabet } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import makeStyles from '@mui/styles/makeStyles';
import { Attribute, AttributeWithMetadata } from '@components/data/csvMapper/representations/attributes/Attribute';
import { useFormikContext } from 'formik';
import { CsvMapper } from '@components/data/csvMapper/CsvMapper';
import CsvMapperRepresentationDialogOption from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationDialogOption';
import CsvMapperRepresentionAttributeSelectedConfigurations from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentionAttributeSelectedConfigurations';
import { useFormatter } from '../../../../../../components/i18n';
import { isEmptyField } from '../../../../../../utils/utils';

const useStyles = makeStyles(() => ({
  container: {
    width: '100%',
    display: 'inline-grid',
    gridTemplateColumns: '1fr 1fr 1fr',
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

interface CsvMapperRepresentationAttributeFormProps {
  indexRepresentation: number;
  attribute: AttributeWithMetadata;
  label: string;
  handleErrors: (key: string, value: string | null) => void;
}

const CsvMapperRepresentationAttributeForm: FunctionComponent<
CsvMapperRepresentationAttributeFormProps
> = ({ indexRepresentation, attribute, label, handleErrors }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const formikContext = useFormikContext<CsvMapper>();
  const selectedAttributes = formikContext.values.representations[indexRepresentation].attributes;
  const indexAttribute = selectedAttributes.findIndex(
    (a) => a.key === attribute.key,
  );

  const options = alphabet(1);

  // -- ERRORS --

  const hasError = attribute.mandatory && isEmptyField(attribute.column?.column_name);
  const [errors, setErrors] = useState(hasError);
  const manageErrors = (value: string | null) => {
    if (attribute.mandatory && isEmptyField(value)) {
      setErrors(true);
    } else {
      setErrors(false);
    }
  };

  // -- EVENTS --

  useEffect(() => {
    if (errors) {
      handleErrors(attribute.key, 'This attribute is required');
    } else {
      handleErrors(attribute.key, null);
    }
  }, [errors]);

  const onValueChange = async (value: string | null) => {
    if (indexAttribute === -1) {
      // this attribute was not set yet, initialize
      const newSelectedAttribute: Attribute = {
        key: attribute.key,
        column: { column_name: value },
        based_on: null,
      };
      await formikContext.setFieldValue(
        `representations[${indexRepresentation}].attributes`,
        [...selectedAttributes, newSelectedAttribute],
      );
    } else if (value === null) {
      // if the column index becomes unset, remove the attributes from selection in formik
      selectedAttributes.splice(indexAttribute, 1);
      await formikContext.setFieldValue(
        `representations[${indexRepresentation}].attributes`,
        selectedAttributes,
      );
    } else {
      await formikContext.setFieldValue(
        `representations[${indexRepresentation}].attributes[${indexAttribute}].column.column_name`,
        value,
      );
    }

    manageErrors(value);
  };

  return (
    <div className={classes.container}>
      <div>
        {label}
        {attribute.mandatory && <span className={classes.redStar}>*</span>}
      </div>
      <div>
        <MUIAutocomplete
          selectOnFocus
          openOnFocus
          autoSelect={false}
          autoHighlight
          options={options}
          // attribute might be unselected yet, but we need value=null as this is a controlled component
          value={
            formikContext.values.representations[indexRepresentation]
              .attributes[indexAttribute]?.column?.column_name || null
          }
          onChange={(_, value) => onValueChange(value)}
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
          (attribute.type === 'date' || attribute.multiple)
          && <CsvMapperRepresentationDialogOption attribute={attribute}>
            <CsvMapperRepresentationAttributeOptions
              attribute={attribute}
              indexRepresentation={indexRepresentation}
            />
          </CsvMapperRepresentationDialogOption>
        }
      </div>
      <CsvMapperRepresentionAttributeSelectedConfigurations
        configuration={ formikContext.values.representations[indexRepresentation]
          .attributes[indexAttribute]?.column?.configuration}
      />

    </div>
  );
};

export default CsvMapperRepresentationAttributeForm;
