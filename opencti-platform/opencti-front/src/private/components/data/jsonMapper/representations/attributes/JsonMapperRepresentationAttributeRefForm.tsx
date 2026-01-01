import React, { FunctionComponent, useEffect, useState } from 'react';
import classNames from 'classnames';
import MuiTextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { representationLabel } from '@components/data/jsonMapper/representations/RepresentationUtils';
import { getBasedOnRepresentations, getInfoForRef } from '@components/data/jsonMapper/representations/attributes/AttributeUtils';
import makeStyles from '@mui/styles/makeStyles';
import { FieldProps } from 'formik';
import { JsonMapperFormData } from '@components/data/jsonMapper/JsonMapper';
import JsonMapperRepresentationDialogOption from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationDialogOption';
import JsonMapperRepresentationAttributeOptions from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributeOptions';
import { JsonMapperRepresentationAttributeFormData } from '@components/data/jsonMapper/representations/attributes/Attribute';
import { JsonMapperRepresentationFormData } from '@components/data/jsonMapper/representations/Representation';
import { SchemaAttribute } from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributesForm';
import { useTheme } from '@mui/styles';
import { isEmptyField } from '../../../../../../utils/utils';
import useAuth from '../../../../../../utils/hooks/useAuth';
import { resolveTypesForRelationship, resolveTypesForRelationshipRef } from '../../../../../../utils/Relation';
import { useFormatter } from '../../../../../../components/i18n';
import { isStixCoreObjects } from '../../../../../../utils/stixTypeUtils';
import type { Theme } from '../../../../../../components/Theme';

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

interface JsonMapperRepresentationAttributeRefFormProps
  extends FieldProps<RepresentationAttributeForm, JsonMapperFormData> {
  representation: JsonMapperRepresentationFormData;
  schemaAttribute: SchemaAttribute;
  label: string;
  handleErrors: (key: string, value: string | null) => void;
}

const JsonMapperRepresentationAttributeRefForm: FunctionComponent<
  JsonMapperRepresentationAttributeRefFormProps
> = ({ form, field, representation, schemaAttribute, label, handleErrors }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const { name, value } = field;
  const isRelationFromOrTo = name.endsWith('from') || name.endsWith('to');
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

  const { schema } = useAuth();
  const { schemaRelationsTypesMapping, schemaRelationsRefTypesMapping } = schema;

  const filterOptions = (representationsOptions: JsonMapperRepresentationFormData[]) => {
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

  let options: JsonMapperRepresentationFormData[] = [];

  // We don't need to resolve those different types, as they can link any entity between them.
  const isGenericRelationship = representation.target?.entity_type === 'related-to'
    || representation.target?.entity_type === 'revoked-by'
    || representation.target?.entity_type === 'stix-sighting-relationship';
  if (isRelationFromOrTo && isGenericRelationship) {
    options = filterOptions(entity_representations);
  } else if (representation.target?.entity_type) {
    const relationshipTypes = resolveTypesForRelationship(
      schemaRelationsTypesMapping,
      representation.target.entity_type,
      schemaAttribute.name,
      fromType,
      toType,
    );
    const relationshipRefTypes = resolveTypesForRelationshipRef(
      schemaRelationsRefTypesMapping,
      representation.target.entity_type,
      schemaAttribute.name,
    );
    const everyRepresentationTypes = [
      ...relationshipTypes,
      ...relationshipRefTypes,
    ];
    if (isStixCoreObjects(everyRepresentationTypes)) {
      schema.sdos.map((sdo) => sdo.label).forEach((sdoType) => everyRepresentationTypes.push(sdoType));
      schema.scos.map((sco) => sco.label).forEach((scoType) => everyRepresentationTypes.push(scoType));
    }
    options = filterOptions(
      entity_representations
        .filter((r) => r.target?.entity_type && everyRepresentationTypes.includes(r.target?.entity_type)),
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

  const handleRepresentationChange = async (
    event: React.SyntheticEvent,
    value: JsonMapperRepresentationFormData[],
  ) => {
    const selectedIds = value.map((v) => v.id);
    const textIdentifiers = (field.value?.based_on?.identifier ?? []).filter((i) => typeof i !== 'string');

    // Add new identifiers for newly selected representations
    const newIdentifiers = [...textIdentifiers];
    selectedIds.forEach((id) => {
      if (!newIdentifiers.find((i) => i.representation === id)) {
        newIdentifiers.push({ identifier: '', representation: id });
      }
    });

    // Remove identifiers for deselected representations
    const finalIdentifiers = newIdentifiers.filter((i) => selectedIds.includes(i.representation ?? ''));

    const updateAttribute: JsonMapperRepresentationAttributeFormData = {
      ...(field.value ?? {}),
      key: schemaAttribute.name,
      mode: 'base',
      based_on: {
        identifier: finalIdentifiers,
        representations: selectedIds,
      },
    };
    await setFieldValue(name, updateAttribute);
  };

  const handleIdentifierChange = async (representationId: string, val: string) => {
    const currentIdentifiers = [...(field.value?.based_on?.identifier ?? [])];
    const index = currentIdentifiers.findIndex((i) => i.representation === representationId);

    if (index >= 0) {
      currentIdentifiers[index] = { ...currentIdentifiers[index], identifier: val };
    } else {
      // Should not happen if sync is correct, but safe fallback
      currentIdentifiers.push({ identifier: val, representation: representationId });
    }

    const updateAttribute: JsonMapperRepresentationAttributeFormData = {
      ...(field.value ?? {}),
      key: schemaAttribute.name,
      mode: 'base',
      based_on: {
        identifier: currentIdentifiers,
        representations: field.value?.based_on?.representations ?? [],
      },
    };
    await setFieldValue(name, updateAttribute);
  };

  return (
    <div className={classes.container} style={{ border: `1px solid ${theme.palette.divider}`, padding: 10 }}>
      <div>
        {label}
        {schemaAttribute.mandatory && <span className={classes.redStar}>*</span>}
      </div>
      <div>
        <MUIAutocomplete<JsonMapperRepresentationFormData, true>
          selectOnFocus
          openOnFocus
          autoSelect={false}
          autoHighlight
          multiple
          getOptionLabel={(option) => representationLabel(entity_representations.indexOf(option), option, t_i18n)}
          options={options}
          value={getBasedOnRepresentations(field.value, options) ?? []}
          onChange={handleRepresentationChange}
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
      </div>
      {schemaAttribute.editDefault ? (
        <JsonMapperRepresentationDialogOption configuration={value}>
          <JsonMapperRepresentationAttributeOptions
            schemaAttribute={schemaAttribute}
            baseAttributeName={name}
            configurationAttributeName={name}
            form={form}
          />
        </JsonMapperRepresentationDialogOption>
      ) : <div />}
      <>
        {(() => {
          const selectedRepresentations = getBasedOnRepresentations(field.value, options);

          if (selectedRepresentations.length === 0) {
            return (
              <>
                <div />
                <div>{t_i18n('Select a representation first')}</div>
                <div />
              </>
            );
          }

          return selectedRepresentations.map((rep) => {
            const identifiers = field.value?.based_on?.identifier ?? [];
            const identifierObj = identifiers.find((i) => i.representation === rep.id);
            const identifierValue = identifierObj?.identifier ?? '';
            return (
              <>
                <div>
                  Identifier ({representationLabel(entity_representations.indexOf(rep), rep, t_i18n)})
                </div>
                <div>
                  <MuiTextField
                    label={t_i18n('JSON Path')}
                    variant="standard"
                    style={{ width: '100%' }}
                    value={identifierValue}
                    onChange={(e) => handleIdentifierChange(rep.id, e.target.value)}
                  />
                </div>
                <div />
              </>
            );
          });
        })()}
      </>
    </div>
  );
};

export default JsonMapperRepresentationAttributeRefForm;
