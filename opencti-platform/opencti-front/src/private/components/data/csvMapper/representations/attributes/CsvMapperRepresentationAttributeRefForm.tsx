import React, { FunctionComponent, useEffect, useState } from 'react';
import classNames from 'classnames';
import MuiTextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { representationLabel } from '@components/data/csvMapper/representations/RepresentationUtils';
import * as R from 'ramda';
import { getBasedOnRepresentations, getInfoForRef } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import makeStyles from '@mui/styles/makeStyles';
import { FieldProps } from 'formik';
import { CsvMapperFormData } from '@components/data/csvMapper/CsvMapper';
import CsvMapperRepresentationDialogOption from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationDialogOption';
import CsvMapperRepresentationAttributeOptions from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributeOptions';
import { CsvMapperRepresentationAttributeFormData } from '@components/data/csvMapper/representations/attributes/Attribute';
import { CsvMapperRepresentationFormData } from '@components/data/csvMapper/representations/Representation';
import {
  CsvMapperRepresentationAttributesForm_allSchemaAttributes$data,
} from '@components/data/csvMapper/representations/attributes/__generated__/CsvMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import { isEmptyField } from '../../../../../../utils/utils';
import useAuth from '../../../../../../utils/hooks/useAuth';
import { resolveTypesForRelationship, resolveTypesForRelationshipRef } from '../../../../../../utils/Relation';
import { useFormatter } from '../../../../../../components/i18n';

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

interface CsvMapperRepresentationAttributeRefFormProps
  extends FieldProps<RepresentationAttributeForm, CsvMapperFormData> {
  representation: CsvMapperRepresentationFormData
  schemaAttribute: CsvMapperRepresentationAttributesForm_allSchemaAttributes$data['csvMapperSchemaAttributes'][number]['attributes'][number];
  label: string;
  handleErrors: (key: string, value: string | null) => void;
}

const CsvMapperRepresentationAttributeRefForm: FunctionComponent<
CsvMapperRepresentationAttributeRefFormProps
> = ({ form, field, representation, schemaAttribute, label, handleErrors }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const { name, value } = field;
  const { setFieldValue, values } = form;
  const { entity_representations } = values;

  const [fromType, fromId] = getInfoForRef(
    Object.values(representation.attributes),
    entity_representations,
    'from',
  );
  const [toType, toId] = getInfoForRef(
    Object.values(representation.attributes),
    entity_representations,
    'to',
  );

  const multiple = schemaAttribute.multiple ?? false;

  const { schema } = useAuth();
  const { schemaRelationsTypesMapping, schemaRelationsRefTypesMapping } = schema;

  const filterOptions = (representationsOptions: CsvMapperRepresentationFormData[]) => {
    return representationsOptions
      .filter((r) => r.id !== representation.id)
      .filter((r) => {
        if (schemaAttribute.name === 'from' && toId) {
          return r.id !== toId;
        }
        if (schemaAttribute.name === 'to' && fromId) {
          return r.id !== fromId;
        }
        return true;
      });
  };

  let options: CsvMapperRepresentationFormData[] = [];

  // For both entity types, whether they are related-to or revoked-by,
  // we don't need to resolve the different types, as they can link any entity between them.
  if (representation.target_type === 'related-to' || representation.target_type === 'revoked-by' || representation.target_type === 'stix-sighting-relationship') {
    options = filterOptions(entity_representations);
  } else if (representation.target_type) {
    const relationshipTypes = resolveTypesForRelationship(
      schemaRelationsTypesMapping,
      representation.target_type,
      schemaAttribute.name,
      fromType,
      toType,
    );
    const relationshipRefTypes = resolveTypesForRelationshipRef(
      schemaRelationsRefTypesMapping,
      representation.target_type,
      schemaAttribute.name,
    );
    options = filterOptions(
      entity_representations
        .filter((r) => r.target_type && [...relationshipTypes, ...relationshipRefTypes].includes(r.target_type)),
    );
  }

  // -- ERRORS --

  const hasErrors = () => {
    const missMandatoryValue = schemaAttribute.mandatory && isEmptyField(value?.based_on);
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

  const onValueChange = async (
    val: CsvMapperRepresentationFormData[] | CsvMapperRepresentationFormData | null,
  ) => {
    let ids: string[] | undefined;
    if (multiple) {
      ids = val ? (val as CsvMapperRepresentationFormData[]).map((r) => r.id) : undefined;
    } else {
      // internally, it's always an array
      ids = val ? [(val as CsvMapperRepresentationFormData).id] : undefined;
    }

    if (!value) {
      // this attribute was not set yet, initialize
      const newAttribute: CsvMapperRepresentationAttributeFormData = {
        key: schemaAttribute.name,
        based_on: ids,
      };
      await setFieldValue(name, newAttribute);
    } else {
      const updateAttribute: CsvMapperRepresentationAttributeFormData = {
        ...value,
        based_on: ids,
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
        {multiple && (
          <MUIAutocomplete<CsvMapperRepresentationFormData, true>
            selectOnFocus
            openOnFocus
            autoSelect={false}
            autoHighlight
            multiple
            getOptionLabel={(option) => representationLabel(entity_representations.indexOf(option), option, t_i18n)}
            options={options}
            value={getBasedOnRepresentations(value, options) || null}
            onChange={(_, val) => onValueChange(val)}
            renderInput={(params) => (
              <MuiTextField
                {...params}
                label={t_i18n('Representation entity')}
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
          <MUIAutocomplete<CsvMapperRepresentationFormData>
            selectOnFocus
            openOnFocus
            autoSelect={false}
            autoHighlight
            getOptionLabel={(option) => representationLabel(entity_representations.indexOf(option), option, t_i18n)}
            options={options}
            value={R.head(getBasedOnRepresentations(value, options)) || null}
            onChange={(_, val) => onValueChange(val)}
            renderInput={(params) => (
              <MuiTextField
                {...params}
                label={t_i18n('Representation entity')}
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
      <div>
        {schemaAttribute.editDefault && (
          <CsvMapperRepresentationDialogOption>
            <CsvMapperRepresentationAttributeOptions
              schemaAttribute={schemaAttribute}
              attributeName={name}
              form={form}
            />
          </CsvMapperRepresentationDialogOption>
        )}
      </div>
    </div>
  );
};

export default CsvMapperRepresentationAttributeRefForm;
