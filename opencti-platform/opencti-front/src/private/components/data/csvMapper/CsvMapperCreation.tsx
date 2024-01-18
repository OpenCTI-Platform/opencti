import React, { FunctionComponent } from 'react';
import { CsvMapperLinesPaginationQuery$variables } from '@components/data/csvMapper/__generated__/CsvMapperLinesPaginationQuery.graphql';
import { FormikConfig } from 'formik';
import { graphql, useMutation } from 'react-relay';
import CsvMapperForm from '@components/data/csvMapper/CsvMapperForm';
import { CsvMapperFormData } from '@components/data/csvMapper/CsvMapper';
import { CsvMapperAddInput } from '@components/data/csvMapper/__generated__/CsvMapperCreationContainerMutation.graphql';
import { formDataToCsvMapper } from '@components/data/csvMapper/CsvMapperUtils';
import { insertNode } from '../../../../utils/store';

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
  onClose?: () => void;
  paginationOptions: CsvMapperLinesPaginationQuery$variables;
}

const CsvMapperCreation: FunctionComponent<CsvMapperCreationFormProps> = ({
  onClose,
  paginationOptions,
}) => {
  const [commit] = useMutation(csvMapperCreation);

  const onSubmit: FormikConfig<CsvMapperFormData>['onSubmit'] = (
    values,
    { resetForm },
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
        resetForm();
        if (onClose) {
          onClose();
        }
      },
    });
  };

  const initialValues: CsvMapperFormData = {
    id: '',
    name: '',
    has_header: false,
    separator: ',',
    skip_line_char: '',
    entity_representations: [],
    relationship_representations: [],
  };

  return <CsvMapperForm csvMapper={initialValues} onSubmit={onSubmit} />;
};

export default CsvMapperCreation;
