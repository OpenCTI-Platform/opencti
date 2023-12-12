import React, { FunctionComponent, useEffect, useState } from 'react';
import classNames from 'classnames';
import MuiTextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { representationLabel } from '@components/data/csvMapper/representations/RepresentationUtils';
import * as R from 'ramda';
import { getBasedOnRepresentations, getInfoForRef } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import makeStyles from '@mui/styles/makeStyles';
import { Attribute, AttributeWithMetadata } from '@components/data/csvMapper/representations/attributes/Attribute';
import { Representation } from '@components/data/csvMapper/representations/Representation';
import { useFormikContext } from 'formik';
import { CsvMapper } from '@components/data/csvMapper/CsvMapper';
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

interface CsvMapperRepresentationAttributeRefFormProps {
  indexRepresentation: number;
  attribute: AttributeWithMetadata;
  label: string;
  handleErrors: (key: string, value: string | null) => void;
}

const CsvMapperRepresentationAttributeRefForm: FunctionComponent<
CsvMapperRepresentationAttributeRefFormProps
> = ({ indexRepresentation, attribute, label, handleErrors }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const formikContext = useFormikContext<CsvMapper>();
  const { representations } = formikContext.values;
  const representation = representations[indexRepresentation];
  const entityType = representation.target.entity_type;
  const indexAttribute = representation.attributes.findIndex(
    (a) => a.key === attribute.key,
  );
  const selectedAttributes = representation.attributes;

  const [fromType, fromId] = getInfoForRef(
    representation.attributes,
    representations,
    'from',
  );
  const [toType, toId] = getInfoForRef(
    representation.attributes,
    representations,
    'to',
  );

  const multiple = attribute.multiple ?? false;

  const { schema } = useAuth();
  const { schemaRelationsTypesMapping, schemaRelationsRefTypesMapping } = schema;

  const filteredOptions = ((representationsOptions: Representation[]) => representationsOptions
    .filter((r) => {
      return r.id !== representation.id;
    })
    .filter((r) => {
      if (attribute.key === 'from' && toId) {
        return r.id !== toId;
      }
      if (attribute.key === 'to' && fromId) {
        return r.id !== fromId;
      }
      return true;
    }));

  let options;

  // For both entity types, whether they are related-to or revoked-by,
  // we don't need to resolve the different types, as they can link any entity between them.
  if (entityType === 'related-to' || entityType === 'revoked-by') {
    options = filteredOptions(representations);
  } else {
    const relationshipTypes = resolveTypesForRelationship(
      schemaRelationsTypesMapping,
      entityType,
      attribute.key,
      fromType,
      toType,
    );
    const relationshipRefTypes = resolveTypesForRelationshipRef(
      schemaRelationsRefTypesMapping,
      entityType,
      attribute.key,
    );
    options = filteredOptions(representations
      .filter((r) => {
        return [...relationshipTypes, ...relationshipRefTypes].includes(
          r.target.entity_type,
        );
      }));
  }

  // -- ERRORS --

  const hasError = attribute.mandatory && isEmptyField(attribute.based_on?.representations);
  const [errors, setErrors] = useState(hasError);
  const manageErrors = (value: Representation[] | Representation | null) => {
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

  const onValueChange = async (
    value: Representation[] | Representation | null,
  ) => {
    let ids: string[];
    if (multiple) {
      ids = value ? (value as Representation[]).map((r) => r.id) : [];
    } else {
      // internally, it's always an array
      ids = value ? [(value as Representation).id] : [];
    }

    if (indexAttribute === -1) {
      // this attribute was not set yet, initialize
      const newSelectedAttribute: Attribute = {
        key: attribute.key,
        column: null,
        based_on: { representations: ids },
      };
      await formikContext.setFieldValue(
        `representations[${indexRepresentation}].attributes`,
        [...selectedAttributes, newSelectedAttribute],
      );
    } else if (value === null) {
      // if the input value becomes unset, remove the attributes from selection in formik
      selectedAttributes.splice(indexAttribute, 1);
      await formikContext.setFieldValue(
        `representations[${indexRepresentation}].attributes`,
        selectedAttributes,
      );
    } else {
      await formikContext.setFieldValue(
        `representations[${indexRepresentation}].attributes[${indexAttribute}].based_on.representations`,
        ids,
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
        {multiple && (
          <MUIAutocomplete
            selectOnFocus
            openOnFocus
            autoSelect={false}
            autoHighlight
            multiple
            getOptionLabel={(option) => representationLabel(representations.indexOf(option), option, t)
            }
            options={options}
            value={getBasedOnRepresentations(attribute, options) || null}
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
        )}
        {!multiple && (
          <MUIAutocomplete
            selectOnFocus
            openOnFocus
            autoSelect={false}
            autoHighlight
            getOptionLabel={(option) => representationLabel(representations.indexOf(option), option, t)
            }
            options={options}
            value={
              R.head(getBasedOnRepresentations(attribute, options)) || null
            }
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
        )}
      </div>
    </div>
  );
};

export default CsvMapperRepresentationAttributeRefForm;
