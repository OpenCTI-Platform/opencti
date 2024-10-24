import React, { FunctionComponent } from 'react';
import { FormikConfig } from 'formik';
import { graphql, useFragment } from 'react-relay';
import { CsvMapperFormData } from '@components/data/csvMapper/CsvMapper';
import { CsvMapperAddInput } from '@components/data/csvMapper/__generated__/CsvMapperCreationContainerMutation.graphql';
import { csvMappers_MappersQuery$variables } from '@components/data/csvMapper/__generated__/csvMappers_MappersQuery.graphql';
import { CsvMapperEditionContainerFragment_csvMapper$key } from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerFragment_csvMapper.graphql';
import { useCsvMappersData } from '@components/data/csvMapper/csvMappers.data';
import {
  CsvMapperRepresentationAttributesForm_allSchemaAttributes$key,
} from '@components/data/csvMapper/representations/attributes/__generated__/CsvMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import { CsvMapperRepresentationAttributesFormFragment } from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributesForm';
import { csvMapperToFormData, formDataToCsvMapper } from '@components/data/csvMapper/CsvMapperUtils';
import CsvMapperForm from '@components/data/csvMapper/CsvMapperForm';
import { csvMapperEditionContainerFragment } from '@components/data/csvMapper/CsvMapperEditionContainer';
import { insertNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';
import { useComputeDefaultValues } from '../../../../utils/hooks/useDefaultValues';

const csvMapperCreation = graphql`
  mutation CsvMapperCreationContainerMutation($input: CsvMapperAddInput!) {
    csvMapperAdd(input: $input) {
      id
      name
      has_header
      separator
      skipLineChar
      errors
    }
  }
`;

interface CsvMapperCreationFormProps {
  paginationOptions: csvMappers_MappersQuery$variables
  isDuplicated?: boolean
  onClose?: () => void
  open: boolean
  mappingCsv?: CsvMapperEditionContainerFragment_csvMapper$key | null,
}

const CsvMapperCreation: FunctionComponent<CsvMapperCreationFormProps> = ({
  mappingCsv,
  isDuplicated,
  onClose,
  paginationOptions,
}) => {
  const [commit] = useApiMutation(csvMapperCreation);
  const { schemaAttributes } = useCsvMappersData();
  const data = useFragment<CsvMapperRepresentationAttributesForm_allSchemaAttributes$key>(
    CsvMapperRepresentationAttributesFormFragment,
    schemaAttributes,
  ) || { csvMapperSchemaAttributes: [] };
  const computeDefaultValues = useComputeDefaultValues();
  const csvMapper = useFragment(
    csvMapperEditionContainerFragment,
    mappingCsv,
  );
  const onSubmit: FormikConfig<CsvMapperFormData>['onSubmit'] = (
    values,
    { resetForm, setSubmitting, setErrors },
  ) => {
    const formattedValues = formDataToCsvMapper(values);
    const input: CsvMapperAddInput = {
      name: formattedValues.name,
      has_header: formattedValues.has_header,
      separator: formattedValues.separator,
      skipLineChar: formattedValues.skipLineChar,
      representations: JSON.stringify(formattedValues.representations),
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => insertNode(
        store,
        'Pagination_csvMappers',
        paginationOptions,
        'csvMapperAdd',
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

  const initialValues: CsvMapperFormData = isDuplicated && csvMapper
    ? csvMapperToFormData(
      {
        ...csvMapper,
        name: `${csvMapper.name} - copy`,
      },
      data.csvMapperSchemaAttributes,
      computeDefaultValues,
    ) : {
      id: '',
      name: '',
      has_header: false,
      separator: ',',
      skip_line_char: '',
      entity_representations: [],
      relationship_representations: [],
    };

  return <CsvMapperForm csvMapper={initialValues} onSubmit={onSubmit} isDuplicated={isDuplicated}/>;
};

export default CsvMapperCreation;
