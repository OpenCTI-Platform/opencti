import { graphql, useLazyLoadQuery } from 'react-relay';
import * as Yup from 'yup';
import { ObjectSchema, ObjectShape, Schema } from 'yup';
import { useSchemaAttributesQuery } from './__generated__/useSchemaAttributesQuery.graphql';
import { useFormatter } from '../../components/i18n';

export const SchemaAttributesQuery = graphql`
  query useSchemaAttributesQuery($entityType: String!) {
    schemaAttributes(entityType: $entityType) {
      name
      mandatory
      multiple
      label
      type
    }
  }
`;

export const useMandatorySchemaAttributes = (
  entityType: string,
):string[] => {
  const data = useLazyLoadQuery<useSchemaAttributesQuery>(
    SchemaAttributesQuery,
    { entityType },
    {
      fetchPolicy: 'store-and-network',
    },
  );
  const mandatoryAttributes = data.schemaAttributes.filter((item) => item.mandatory).map((ele) => ele.name);
  return mandatoryAttributes;
};

export const useYupSchemaBuilder = (
  entityType: string,
  existingShape: ObjectShape,
  isCreation: boolean,
  exclusions?: string[],
): ObjectSchema<{ [p: string]: unknown }> => {
  // simplest case: we're in update mode, so we do not need all mandatory fields
  if (!isCreation) {
    return Yup.object().shape(existingShape);
  }
  // we're in creation mode, let's find if all mandatory fields are set
  const { t_i18n } = useFormatter();
  const mandatoryAttributes = useMandatorySchemaAttributes(entityType);
  const existingKeys = Object.keys(existingShape);
  const newShape: ObjectShape = Object.fromEntries(
    mandatoryAttributes
      .filter((attr) => !(exclusions ?? []).includes(attr))
      .map((attrName: string) => {
        let validator: Schema;
        if (existingKeys.includes(attrName)) {
          validator = (existingShape[attrName] as Schema)
            .transform((v) => ((Array.isArray(v) && v.length === 0) ? undefined : v))
            .required(t_i18n('This field is required'))
            .nullable(false);
        } else {
          validator = Yup.mixed()
            .transform((v) => ((Array.isArray(v) && v.length === 0) ? undefined : v))
            .required(t_i18n('This field is required'));
        }
        return [attrName, validator];
      }),
  );
  return Yup.object().shape({ ...existingShape, ...newShape });
};

export const useSchemaCreationValidation = (
  entityType: string,
  existingShape: ObjectShape,
  exclusions?: string[],
): ObjectSchema<{ [p: string]: unknown }> => {
  return useYupSchemaBuilder(entityType, existingShape, true, exclusions);
};

export const useSchemaEditionValidation = (
  entityType: string,
  existingShape: ObjectShape,
  exclusions?: string[],
): ObjectSchema<{ [p: string]: unknown }> => {
  return useYupSchemaBuilder(entityType, existingShape, false, exclusions);
};
