import React, { FunctionComponent } from 'react';
import { FormikConfig } from 'formik';
import { graphql, useFragment } from 'react-relay';
import { JsonMapperFormData } from '@components/data/jsonMapper/JsonMapper';
import { jsonMappers_MappersQuery$variables } from '@components/data/jsonMapper/__generated__/jsonMappers_MappersQuery.graphql';
import { useJsonMappersData } from '@components/data/jsonMapper/jsonMappers.data';
import { JsonMapperRepresentationAttributesFormFragment } from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributesForm';
import { formDataToJsonMapper, jsonMapperToFormData } from '@components/data/jsonMapper/JsonMapperUtils';
import JsonMapperForm from '@components/data/jsonMapper/JsonMapperForm';
import { jsonMapperEditionContainerFragment } from '@components/data/jsonMapper/JsonMapperEditionContainer';
import { JsonMapperEditionContainerFragment_jsonMapper$key } from '@components/data/jsonMapper/__generated__/JsonMapperEditionContainerFragment_jsonMapper.graphql';
import { JsonMapperAddInput } from '@components/data/jsonMapper/__generated__/JsonMapperCreationContainerMutation.graphql';
import {
  JsonMapperRepresentationAttributesForm_allSchemaAttributes$key,
} from '@components/data/jsonMapper/representations/attributes/__generated__/JsonMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useComputeDefaultValues } from '../../../../utils/hooks/useDefaultValues';
import { handleErrorInForm } from '../../../../relay/environment';
import { insertNode } from '../../../../utils/store';

const jsonMapperCreation = graphql`
  mutation JsonMapperCreationContainerMutation($input: JsonMapperAddInput!) {
    jsonMapperAdd(input: $input) {
      id
      name
      errors
    }
  }
`;

interface JsonMapperCreationFormProps {
  paginationOptions: jsonMappers_MappersQuery$variables
  isDuplicated?: boolean
  onClose?: () => void
  mappingJson?: JsonMapperEditionContainerFragment_jsonMapper$key | null,
}

const JsonMapperCreation: FunctionComponent<JsonMapperCreationFormProps> = ({
  mappingJson,
  isDuplicated,
  onClose,
  paginationOptions,
}) => {
  const [commit] = useApiMutation(jsonMapperCreation);
  const { schemaAttributes } = useJsonMappersData();
  const data = useFragment<JsonMapperRepresentationAttributesForm_allSchemaAttributes$key>(
    JsonMapperRepresentationAttributesFormFragment,
    schemaAttributes,
  ) || { csvMapperSchemaAttributes: [] };

  const computeDefaultValues = useComputeDefaultValues();
  const jsonMapper = useFragment(
    jsonMapperEditionContainerFragment,
    mappingJson,
  );
  const onSubmit: FormikConfig<JsonMapperFormData>['onSubmit'] = (
    values,
    { resetForm, setSubmitting, setErrors },
  ) => {
    const formattedValues = formDataToJsonMapper(values);
    const input: JsonMapperAddInput = {
      name: formattedValues.name,
      representations: JSON.stringify(formattedValues.representations),
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => insertNode(
        store,
        'Pagination_jsonMappers',
        paginationOptions,
        'jsonMapperAdd',
      ),
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onClose) {
          onClose();
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  let initialValues: JsonMapperFormData = {
    id: '',
    name: '',
    entity_representations: [],
    relationship_representations: [],
  };
  if (isDuplicated && jsonMapper) {
    initialValues = jsonMapperToFormData(
      { ...jsonMapper, name: `${jsonMapper.name} - copy` },
      data.csvMapperSchemaAttributes,
      computeDefaultValues,
    );
  }
  return <JsonMapperForm attributes={data.csvMapperSchemaAttributes} jsonMapper={initialValues} onSubmit={onSubmit} isDuplicated={isDuplicated}/>;
};

export default JsonMapperCreation;
