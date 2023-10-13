import React, { FunctionComponent } from 'react';
import {
  CsvMapperLinesPaginationQuery$variables,
} from '@components/data/csvMapper/__generated__/CsvMapperLinesPaginationQuery.graphql';
import { FormikConfig } from 'formik';
import { graphql, useMutation } from 'react-relay';
import CsvMapperForm from '@components/data/csvMapper/CsvMapperForm';
import { sanitized } from '@components/data/csvMapper/representations/RepresentationUtils';
import { CsvMapper } from '@components/data/csvMapper/CsvMapper';
import { CsvMapperAddInput } from '@components/data/csvMapper/__generated__/CsvMapperCreationContainerMutation.graphql';
import { insertNode } from '../../../../utils/store';

const csvMapperCreation = graphql`
  mutation CsvMapperCreationContainerMutation($input: CsvMapperAddInput!) {
    csvMapperAdd(input: $input) {
      id
      name
      has_header
      separator
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
  const onSubmit: FormikConfig<CsvMapper>['onSubmit'] = (
    values,
    { resetForm },
  ) => {
    const input: CsvMapperAddInput = {
      name: values.name,
      has_header: values.has_header,
      separator: values.separator,
      representations: JSON.stringify(sanitized(values.representations)),
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

  const initialValues: CsvMapper = {
    name: '',
    has_header: false,
    separator: ',',
    representations: [],
    errors: null,
  };

  return (
    <CsvMapperForm csvMapper={initialValues} onSubmit={onSubmit}/>
  );
};

export default CsvMapperCreation;
