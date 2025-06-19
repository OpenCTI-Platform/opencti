import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import JsonMapperRepresentationAttributeForm from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributeForm';
import { getAttributeLabel } from '@components/data/jsonMapper/representations/attributes/AttributeUtils';
import { Field } from 'formik';
import JsonMapperRepresentationAttributeRefForm from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributeRefForm';
import { JsonMapperRepresentationFormData } from '@components/data/jsonMapper/representations/Representation';
import {
  JsonMapperRepresentationAttributesForm_allSchemaAttributes$key,
} from '@components/data/jsonMapper/representations/attributes/__generated__/JsonMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import { useJsonMappersData } from '../../jsonMappers.data';
import { useFormatter } from '../../../../../../components/i18n';
import TextField from '../../../../../../components/TextField';
import type { Theme } from '../../../../../../components/Theme';
import { isEmptyField } from '../../../../../../utils/utils';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    width: '100%',
    display: 'inline-grid',
    gridTemplateColumns: '2fr 3fr 50px',
    alignItems: 'center',
    padding: 10,
    marginTop: 20,
    marginBottom: 10,
    gap: '10px',
  },
  redStar: {
    color: 'rgb(244, 67, 54)',
    marginLeft: '5px',
  },
}));

export const JsonMapperRepresentationAttributesFormFragment = graphql`
  fragment JsonMapperRepresentationAttributesForm_allSchemaAttributes on Query {
    csvMapperSchemaAttributes {
      name
      attributes {
        name
        label
        editDefault
        mandatory
        multiple
        type
        defaultValues {
          name
          id
        }
        mappings {
          name
          type
          multiple
          label
          mandatory
          editDefault
        }
      }
    }
  }
`;

export interface SchemaAttribute {
  type: string
  name: string
  label: string | null | undefined
  mandatory: boolean
  defaultValues: { readonly id: string, readonly name: string }[] | null
  multiple: boolean
  editDefault: boolean
}

interface JsonMapperRepresentationAttributesFormProps {
  handleErrors: (key: string, value: string | null) => void;
  representation: JsonMapperRepresentationFormData
  representationType: string
  representationName: string
}

const JsonMapperRepresentationAttributesForm: FunctionComponent<
JsonMapperRepresentationAttributesFormProps
> = ({ handleErrors, representation, representationType, representationName }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const classes = useStyles();
  const { schemaAttributes } = useJsonMappersData();
  const data = useFragment<JsonMapperRepresentationAttributesForm_allSchemaAttributes$key>(
    JsonMapperRepresentationAttributesFormFragment,
    schemaAttributes,
  );

  if (representation.target?.entity_type === null) {
    // if the entity type gets unset, we display nothing
    // when user will select a new entity type, attributes will be fetched
    return null;
  }

  const entitySchemaAttributes = data?.csvMapperSchemaAttributes?.find(
    (schema) => schema.name === representation.target?.entity_type,
  )?.attributes ?? [];

  const mutableSchemaAttributes: SchemaAttribute[] = entitySchemaAttributes.map((schema) => {
    if (schema.name === 'hashes') {
      return (schema.mappings ?? []).map((mapping) => ({
        ...mapping,
        defaultValues: null,
      }));
    }
    return [{
      type: schema.type,
      name: schema.name,
      label: schema.label,
      mandatory: schema.mandatory,
      multiple: schema.multiple,
      editDefault: schema.editDefault,
      defaultValues: schema.defaultValues ? [...schema.defaultValues] : null,
    }];
  }).flat();

  return (
    <>
      {mutableSchemaAttributes.length > 0 && <div className={classes.container} style={{ border: `1px solid ${theme.palette.divider}` }}>
        <div>
          Entity path mapping <span className={classes.redStar}>*</span>
        </div>
        <div>
          <Field
            component={TextField}
            label={t_i18n('JSON Path')}
            required={true}
            name={`${representationName}.target.path`}
            variant='standard'
            style={{ width: '100%' }}
            onChange={(_event: React.SyntheticEvent, newValue: string) => {
              handleErrors('target.path', isEmptyField(newValue) ? 'This field is required' : null);
            }}
          />
        </div>
        <div/>
        { representationType === 'entity' && <>
          <div>
            Identifier
          </div>
          <div>
            <Field
              component={TextField}
              label={t_i18n('JSON Path')}
              name={`${representationName}.identifier`}
              variant='standard'
              style={{ width: '100%' }}
            />
          </div>
        </>}
      </div>}
      {[...mutableSchemaAttributes]
        .sort((a1, a2) => Number(a2.mandatory) - Number(a1.mandatory))
        .map((schemaAttribute) => {
          if (schemaAttribute.type === 'ref') {
            return (
              <Field
                component={JsonMapperRepresentationAttributeRefForm}
                key={schemaAttribute.name}
                name={`${representationName}.attributes.${schemaAttribute.name}`}
                schemaAttribute={schemaAttribute}
                label={t_i18n(getAttributeLabel(schemaAttribute)).toLowerCase()}
                handleErrors={handleErrors}
                representation={representation}
              />
            );
          }
          return (
            <Field
              component={JsonMapperRepresentationAttributeForm}
              key={schemaAttribute.name}
              name={`${representationName}.attributes.${schemaAttribute.name}`}
              schemaAttribute={schemaAttribute}
              label={t_i18n(getAttributeLabel(schemaAttribute)).toLowerCase()}
              handleErrors={handleErrors}
            />
          );
        })}
    </>
  );
};

export default JsonMapperRepresentationAttributesForm;
