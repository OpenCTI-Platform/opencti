import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { Formik } from 'formik';
import * as R from 'ramda';
import CsvMapperRepresentationAttributeForm
  from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributeForm';
import CsvMapperRepresentationBasedOnForm
  from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationBasedOnForm';
import {
  attributeLabel,
  convertFromSchemaAttribute,
  entityTypeAttributeFrom,
  entityTypeAttributeTo,
} from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import { Representation } from '@components/data/csvMapper/representations/Representation';
import {
  CsvMapperRepresentationAttributesFormQuery,
} from '@components/data/csvMapper/representations/attributes/__generated__/CsvMapperRepresentationAttributesFormQuery.graphql';
import { useFormatter } from '../../../../../../components/i18n';
import { Attribute } from './Attribute';

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
  queryRef: PreloadedQuery<CsvMapperRepresentationAttributesFormQuery>;
  entityType: string;
  representations: Representation[];
  attributes: Attribute[];
  setAttributes: (attributes: Attribute[]) => void;
  handleErrors: (key: string, value: string | null) => void;
}

const CsvMapperRepresentationAttributesForm: FunctionComponent<CsvMapperRepresentationAttributesFormProps> = ({
  queryRef,
  entityType,
  representations,
  attributes,
  setAttributes,
  handleErrors,
}) => {
  const { t } = useFormatter();

  // -- INIT --

  const { schemaAttributes } = usePreloadedQuery<CsvMapperRepresentationAttributesFormQuery>(
    schemaAttributesQuery,
    queryRef,
  );

  const computeSelectedAttributes = () => {
    const computedAttributes: Attribute[] = [];
    schemaAttributes.forEach((schemaAttribute) => {
      if (schemaAttribute) {
        const existingAttribute = attributes.find((a) => schemaAttribute.name === a.key);
        if (!existingAttribute) {
          computedAttributes.push(convertFromSchemaAttribute(schemaAttribute));
        } else {
          computedAttributes.push({
            ...existingAttribute,
            type: schemaAttribute.type,
            mandatory: schemaAttribute.mandatory,
            multiple: schemaAttribute.multiple,
          });
        }
      }
    });
    return computedAttributes.sort((a1, a2) => Number(a2.mandatory) - Number(a1.mandatory));
  };

  const [selectedAttributes, setSelectedAttributes] = useState<Attribute[]>(computeSelectedAttributes());

  const fromType = entityTypeAttributeFrom(selectedAttributes, representations);
  const toType = entityTypeAttributeTo(selectedAttributes, representations);

  // -- EVENTS --

  useEffect(() => {
    setSelectedAttributes(computeSelectedAttributes);
  }, [schemaAttributes]);

  const handleChangeValue = (attribute: Attribute, name: string, value: string | string[] | boolean | null) => {
    const newAttribute = R.assocPath(name.split('.'), value, attribute);
    const newAttributes = selectedAttributes.map((a) => {
      if (a.key === newAttribute.key) {
        return newAttribute;
      }
      return a;
    });
    setSelectedAttributes(newAttributes);
    setAttributes(newAttributes);
  };

  return (
    <>
      {selectedAttributes.map((attribute) => (
        <Formik
          key={attribute.key}
          initialValues={attribute}
          onSubmit={() => {}}
        >
          {() => {
            if (attribute.type === 'ref') {
              return (
                <CsvMapperRepresentationBasedOnForm
                  basedOn={attribute}
                  fromType={fromType}
                  toType={toType}
                  label={t(attributeLabel(attribute, schemaAttributes)).toLowerCase()}
                  entityType={entityType}
                  representations={representations}
                  onChange={handleChangeValue}
                  handleErrors={handleErrors}
                />
              );
            }
            return (
              <CsvMapperRepresentationAttributeForm
                attribute={attribute}
                label={t(attributeLabel(attribute, schemaAttributes)).toLowerCase()}
                onChange={handleChangeValue}
                handleErrors={handleErrors}
              />
            );
          }}
        </Formik>
      ))}
    </>
  );
};

export default CsvMapperRepresentationAttributesForm;
