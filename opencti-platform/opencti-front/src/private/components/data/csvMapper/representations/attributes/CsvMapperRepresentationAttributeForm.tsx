import React, { FunctionComponent, useEffect, useState } from 'react';
import MUIAutocomplete from '@mui/material/Autocomplete';
import MuiTextField from '@mui/material/TextField';
import classNames from 'classnames';
import CsvMapperRepresentationAttributeOptions
  from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributeOptions';
import { alphabet } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import makeStyles from '@mui/styles/makeStyles';
import { Attribute } from '@components/data/csvMapper/representations/attributes/Attribute';
import { useFormatter } from '../../../../../../components/i18n';
import { isEmptyField } from '../../../../../../utils/utils';

const useStyles = makeStyles(() => ({
  container: {
    width: '100%',
    display: 'inline-grid',
    gridTemplateColumns: '1fr 1fr 1fr',
    alignItems: 'center',
    marginTop: '10px',
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
  attribute: Attribute;
  label: string;
  onChange: (attribute: Attribute, name: string, value: string | string[] | boolean | null) => void;
  handleErrors: (key: string, value: string | null) => void;
}

const CsvMapperRepresentationAttributeForm: FunctionComponent<CsvMapperRepresentationAttributeFormProps> = ({
  attribute,
  label,
  onChange,
  handleErrors,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

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

  const onValueChange = (value: string | null) => {
    onChange(attribute, 'column.column_name', value);
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
          defaultValue={attribute.column?.column_name}
          onChange={(_, value) => onValueChange(value)}
          renderInput={(params) => (
            <MuiTextField
              {...params}
              label={t('Column index')}
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
        <CsvMapperRepresentationAttributeOptions attribute={attribute} onChange={onChange}/>
      </div>
    </div>
  );
};

export default CsvMapperRepresentationAttributeForm;
