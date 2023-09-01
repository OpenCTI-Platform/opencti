import React, { FunctionComponent } from 'react';
import { graphql, useMutation } from 'react-relay';
import * as R from 'ramda';
import { FormikConfig } from 'formik/dist/types';
import {
  CsvMapperEditionContainerFragment_csvMapper$data,
} from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerFragment_csvMapper.graphql';
import CsvMapperForm from '@components/data/csvMapper/CsvMapperForm';
import { useMapRepresentations, sanitized } from '@components/data/csvMapper/representations/RepresentationUtils';
import { CsvMapper } from '@components/data/csvMapper/CsvMapper';
import formikFieldToEditInput from '../../../../utils/FormikUtils';

const csvMapperEditionPatch = graphql`
  mutation CsvMapperEditionPatchMutation($id: ID!, $input: [EditInput!]!) {
    csvMapperFieldPatch(id: $id, input: $input) {
      ...CsvMapperEditionContainerFragment_csvMapper
    }
  }
`;

interface CsvMapperEditionProps {
  csvMapper: CsvMapperEditionContainerFragment_csvMapper$data;
  onClose?: () => void;
}

const CsvMapperEdition: FunctionComponent<CsvMapperEditionProps> = ({
  csvMapper,
  onClose,
}) => {
  const [commitUpdateMutation] = useMutation(csvMapperEditionPatch);

  const initialValues: CsvMapper = {
    id: csvMapper.id,
    name: csvMapper.name,
    has_header: csvMapper.has_header,
    separator: csvMapper.separator,
    representations: useMapRepresentations(csvMapper.representations),
    errors: csvMapper.errors,
  };

  const onSubmit: FormikConfig<CsvMapper>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const input = formikFieldToEditInput(
      {
        ...R.omit(['id', 'errors'], values),
        representations: JSON.stringify(sanitized(values.representations)),
      },
      {
        name: csvMapper.name,
        representations: JSON.stringify(csvMapper.representations),
      },
    );
    if (input.length > 0) {
      commitUpdateMutation({
        variables: { id: csvMapper.id, input },
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

  return (
    <CsvMapperForm csvMapper={initialValues} onSubmit={onSubmit}/>
  );
};

export default CsvMapperEdition;
