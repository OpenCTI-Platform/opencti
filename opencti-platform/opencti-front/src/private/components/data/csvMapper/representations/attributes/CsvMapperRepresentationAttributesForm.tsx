import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { useFormikContext } from 'formik';

import CsvMapperRepresentationAttributeForm from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributeForm';

import { getAttributeLabel, convertFromSchemaAttribute } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import { CsvMapperRepresentationAttributesFormQuery } from '@components/data/csvMapper/representations/attributes/__generated__/CsvMapperRepresentationAttributesFormQuery.graphql';
import { CsvMapper } from '@components/data/csvMapper/CsvMapper';
import CsvMapperRepresentationAttributeRefForm from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributeRefForm';
import { useFormatter } from '../../../../../../components/i18n';
import { AttributeWithMetadata } from './Attribute';

export const schemaAttributesQuery = graphql`
  query CsvMapperRepresentationAttributesFormQuery($entityType: String!) {
    schemaAttributes(entityType: $entityType) {
      name
      mandatory
      multiple
      label
      type
    }
  }
`;

interface CsvMapperRepresentationAttributesFormProps {
  index: number;
  queryRef: PreloadedQuery<CsvMapperRepresentationAttributesFormQuery>;
  handleErrors: (key: string, value: string | null) => void;
}

const CsvMapperRepresentationAttributesForm: FunctionComponent<
CsvMapperRepresentationAttributesFormProps
> = ({ index, queryRef, handleErrors }) => {
  const { t } = useFormatter();

  const formikContext = useFormikContext<CsvMapper>();
  const representation = formikContext.values.representations[index];
  const entityType = representation.target.entity_type;
  const { attributes: selectedAttributes } = representation;

  // -- INIT --

  // some fields are not present in the csv mapper but in the schema
  // we enhance these attributes with the schema data, to use in our form
  const { schemaAttributes } = usePreloadedQuery<CsvMapperRepresentationAttributesFormQuery>(
    schemaAttributesQuery,
    queryRef,
  );

  // we build the full list of attributes for this entity type
  const addMetadataToAttributes = () => {
    const computedAttributes: AttributeWithMetadata[] = [];
    schemaAttributes.forEach((schemaAttribute) => {
      const existingAttribute = selectedAttributes.find(
        (a) => schemaAttribute.name === a.key,
      );
      if (!existingAttribute) {
        // init the attribute (unset by user)
        computedAttributes.push(convertFromSchemaAttribute(schemaAttribute));
      } else {
        // the existing CSV Mapper data are enhanced with schema metadata
        computedAttributes.push({
          ...existingAttribute,
          type: schemaAttribute.type,
          mandatory: schemaAttribute.mandatory,
          multiple: schemaAttribute.multiple,
        });
      }
    });
    return computedAttributes.sort(
      (a1, a2) => Number(a2.mandatory) - Number(a1.mandatory),
    );
  };

  const [attributesWithMetadata, setAttributesWithMetadata] = useState<
  AttributeWithMetadata[]
  >([]);

  // -- EVENTS --

  useEffect(() => {
    // rebuild the enhanced attributes on changes of schema (should be only at start)
    // or on changes of values (on formik context updated)
    setAttributesWithMetadata(addMetadataToAttributes());
  }, [schemaAttributes, selectedAttributes]);

  if (entityType === null) {
    // if the entity type gets unset, we display nothing
    // when user will select a new entity type, attributes will be fetched
    return null;
  }

  return (
    <>
      {attributesWithMetadata.map((availableAttribute) => {
        if (availableAttribute.type === 'ref') {
          return (
            <CsvMapperRepresentationAttributeRefForm
              key={availableAttribute.key}
              indexRepresentation={index}
              attribute={availableAttribute}
              label={t(
                getAttributeLabel(availableAttribute, schemaAttributes),
              ).toLowerCase()}
              handleErrors={handleErrors}
            />
          );
        }
        return (
          <CsvMapperRepresentationAttributeForm
            key={availableAttribute.key}
            indexRepresentation={index}
            attribute={availableAttribute}
            label={t(
              getAttributeLabel(availableAttribute, schemaAttributes),
            ).toLowerCase()}
            handleErrors={handleErrors}
          />
        );
      })}
    </>
  );
};

export default CsvMapperRepresentationAttributesForm;
