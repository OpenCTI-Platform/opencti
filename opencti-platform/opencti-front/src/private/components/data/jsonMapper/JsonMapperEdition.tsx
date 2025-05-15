import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import * as R from 'ramda';
import { FormikConfig } from 'formik/dist/types';
import JsonMapperForm from '@components/data/jsonMapper/JsonMapperForm';
import { JsonMapperFormData } from '@components/data/jsonMapper/JsonMapper';
import { formDataToJsonMapper, jsonMapperToFormData } from '@components/data/jsonMapper/JsonMapperUtils';
import { useJsonMappersData } from '@components/data/jsonMapper/jsonMappers.data';
import { JsonMapperRepresentationAttributesFormFragment } from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributesForm';
import { JsonMapperEditionContainerFragment_jsonMapper$data } from '@components/data/jsonMapper/__generated__/JsonMapperEditionContainerFragment_jsonMapper.graphql';
import {
  JsonMapperRepresentationAttributesForm_allSchemaAttributes$key,
} from '@components/data/jsonMapper/representations/attributes/__generated__/JsonMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import formikFieldToEditInput from '../../../../utils/FormikUtils';
import { useComputeDefaultValues } from '../../../../utils/hooks/useDefaultValues';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const jsonMapperEditionPatch = graphql`
  mutation JsonMapperEditionPatchMutation($id: ID!, $input: [EditInput!]!) {
    jsonMapperFieldPatch(id: $id, input: $input) {
      ...JsonMapperEditionContainerFragment_jsonMapper
    }
  }
`;

interface JsonMapperEditionProps {
  jsonMapper: JsonMapperEditionContainerFragment_jsonMapper$data;
  onClose?: () => void;
}

const JsonMapperEdition: FunctionComponent<JsonMapperEditionProps> = ({
  jsonMapper,
  onClose,
}) => {
  const [commitUpdateMutation] = useApiMutation(jsonMapperEditionPatch);
  const { schemaAttributes } = useJsonMappersData();
  const data = useFragment<JsonMapperRepresentationAttributesForm_allSchemaAttributes$key>(
    JsonMapperRepresentationAttributesFormFragment,
    schemaAttributes,
  );

  if (!data) {
    return null;
  }

  const computeDefaultValues = useComputeDefaultValues();
  const initialValues = jsonMapperToFormData(
    jsonMapper,
    data.csvMapperSchemaAttributes,
    computeDefaultValues,
  );

  const onSubmit: FormikConfig<JsonMapperFormData>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const formattedValues = formDataToJsonMapper(values);
    const input = formikFieldToEditInput(
      {
        ...R.omit(['id'], formattedValues),
        representations: JSON.stringify(formattedValues.representations),
      },
      {
        name: jsonMapper.name,
        representations: JSON.stringify(jsonMapper.representations),
      },
    );
    if (input.length > 0) {
      commitUpdateMutation({
        variables: { id: jsonMapper.id, input },
        onCompleted: () => {
          setSubmitting(false);
          if (onClose) {
            onClose();
          }
        },
      });
    } else {
      setSubmitting(false);
      if (onClose) {
        onClose();
      }
    }
  };

  return <JsonMapperForm attributes={data.csvMapperSchemaAttributes} jsonMapper={initialValues} onSubmit={onSubmit} />;
};

export default JsonMapperEdition;
