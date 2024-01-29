import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import CsvMapperRepresentationAttributeForm from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributeForm';
import { getAttributeLabel } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import { Field } from 'formik';
import CsvMapperRepresentationAttributeRefForm from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributeRefForm';
import { CsvMapperRepresentationFormData } from '@components/data/csvMapper/representations/Representation';
import {
  CsvMapperRepresentationAttributesForm_allSchemaAttributes$key,
} from '@components/data/csvMapper/representations/attributes/__generated__/CsvMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import { useCsvMappersData } from '../../csvMappers.data';
import { useFormatter } from '../../../../../../components/i18n';

export const CsvMapperRepresentationAttributesFormFragment = graphql`
  fragment CsvMapperRepresentationAttributesForm_allSchemaAttributes on Query {
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

interface CsvMapperRepresentationAttributesFormProps {
  handleErrors: (key: string, value: string | null) => void;
  representation: CsvMapperRepresentationFormData
  representationName: string
}

const CsvMapperRepresentationAttributesForm: FunctionComponent<
CsvMapperRepresentationAttributesFormProps
> = ({ handleErrors, representation, representationName }) => {
  const { t_i18n } = useFormatter();
  const { schemaAttributes } = useCsvMappersData();
  const data = useFragment<CsvMapperRepresentationAttributesForm_allSchemaAttributes$key>(
    CsvMapperRepresentationAttributesFormFragment,
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
                component={CsvMapperRepresentationAttributeRefForm}
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
              component={CsvMapperRepresentationAttributeForm}
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

export default CsvMapperRepresentationAttributesForm;
