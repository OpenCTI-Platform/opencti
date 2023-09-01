import React, { FunctionComponent, useEffect, useState } from 'react';
import classNames from 'classnames';
import MuiTextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { representationLabel } from '@components/data/csvMapper/representations/RepresentationUtils';
import * as R from 'ramda';
import { basedOnValue } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import makeStyles from '@mui/styles/makeStyles';
import { Attribute } from '@components/data/csvMapper/representations/attributes/Attribute';
import { Representation } from '@components/data/csvMapper/representations/Representation';
import { isEmptyField } from '../../../../../../utils/utils';
import useAuth from '../../../../../../utils/hooks/useAuth';
import { resolveTypesForRelationship, resolveTypesForRelationshipRef } from '../../../../../../utils/Relation';
import { useFormatter } from '../../../../../../components/i18n';

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

interface CsvMapperRepresentationFromAndToFormProps {
  basedOn: Attribute;
  label: string;
  onChange: (basedOn: Attribute, name: string, value: string | string[] | boolean | null) => void;
  handleErrors: (key: string, value: string | null) => void;
  entityType: string;
  representations: Representation[];
  fromType?: string;
  toType?: string;
}

const CsvMapperRepresentationBasedOnForm: FunctionComponent<CsvMapperRepresentationFromAndToFormProps> = ({
  basedOn,
  label,
  onChange,
  handleErrors,
  entityType,
  representations,
  fromType,
  toType,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const multiple = basedOn.multiple ?? false;

  const { schema } = useAuth();
  const { schemaRelationsTypesMapping, schemaRelationsRefTypesMapping } = schema;
  const relationshipTypes = resolveTypesForRelationship(schemaRelationsTypesMapping, entityType, basedOn.key, fromType, toType);
  const relationshipRefTypes = resolveTypesForRelationshipRef(schemaRelationsRefTypesMapping, entityType, basedOn.key);
  const options = representations.filter((r) => {
    return [...relationshipTypes, ...relationshipRefTypes].includes(r.target.entity_type);
  });

  // -- ERRORS --

  const hasError = basedOn.mandatory && isEmptyField(basedOn.based_on?.representations);
  const [errors, setErrors] = useState(hasError);
  const manageErrors = (value: Representation[] | Representation | null) => {
    if (basedOn.mandatory && isEmptyField(value)) {
      setErrors(true);
    } else {
      setErrors(false);
    }
  };

  // -- EVENTS --

  useEffect(() => {
    if (errors) {
      handleErrors(basedOn.key, 'This attribute is required');
    } else {
      handleErrors(basedOn.key, null);
    }
  }, [errors]);

  const onValueChange = (value: Representation[] | Representation | null) => {
    // eslint-disable-next-line no-nested-ternary
    const newValue = Array.isArray(value) ? (value?.map((v) => v.id)) : (value ? [value.id] : []);
    onChange(basedOn, 'based_on.representations', newValue);
    manageErrors(value);
  };

  useEffect(() => {
    const initValue = basedOnValue(basedOn, options);
    onChange(basedOn, 'based_on.representations', initValue?.map((v) => v.id));
  }, [representations]);

  return (
    <div className={classes.container}>
      <div>
        {label}
        {basedOn.mandatory && <span className={classes.redStar}>*</span>}
      </div>
      <div>
        {multiple
        && <MUIAutocomplete
            selectOnFocus
            openOnFocus
            autoSelect={false}
            autoHighlight
            multiple
            getOptionLabel={(option) => representationLabel(representations.indexOf(option), option)}
            options={options}
            defaultValue={basedOnValue(basedOn, options)}
            onChange={(_, value) => onValueChange(value)}
            renderInput={(params) => (
              <MuiTextField
                {...params}
                label={t('Representation entity')}
                variant="outlined"
                size="small"
              />
            )}
            className={classNames({
              [classes.inputError]: errors,
            })}
          />
        }
        {!multiple
        && <MUIAutocomplete
            selectOnFocus
            openOnFocus
            autoSelect={false}
            autoHighlight
            getOptionLabel={(option) => representationLabel(representations.indexOf(option), option)}
            options={options}
            defaultValue={R.head(basedOnValue(basedOn, options))}
            onChange={(_, value) => onValueChange(value)}
            renderInput={(params) => (
              <MuiTextField
                {...params}
                label={t('Representation entity')}
                variant="outlined"
                size="small"
              />
            )}
            className={classNames({
              [classes.inputError]: errors,
            })}
          />
        }
      </div>
    </div>
  );
};

export default CsvMapperRepresentationBasedOnForm;
