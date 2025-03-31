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
import { useJsonMappersData } from '../../jsonMappers.data';
import { useFormatter } from '../../../../../../components/i18n';

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
  representationName: string
}

const JsonMapperRepresentationAttributesForm: FunctionComponent<
JsonMapperRepresentationAttributesFormProps
> = ({ handleErrors, representation, representationName }) => {
  const { t_i18n } = useFormatter();
  const { schemaAttributes } = useJsonMappersData();
  const data = useFragment<JsonMapperRepresentationAttributesForm_allSchemaAttributes$key>(
    JsonMapperRepresentationAttributesFormFragment,
    schemaAttributes,
  );

  if (representation.target_type === null) {
    // if the entity type gets unset, we display nothing
    // when user will select a new entity type, attributes will be fetched
    return null;
  }

  const entitySchemaAttributes = data?.csvMapperSchemaAttributes?.find(
    (schema) => schema.name === representation.target_type,
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
