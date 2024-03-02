import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import * as R from 'ramda';
import { FormikConfig } from 'formik/dist/types';
import { CsvMapperEditionContainerFragment_csvMapper$data } from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerFragment_csvMapper.graphql';
import CsvMapperForm from '@components/data/csvMapper/CsvMapperForm';
import { CsvMapperFormData } from '@components/data/csvMapper/CsvMapper';
import { csvMapperToFormData, formDataToCsvMapper } from '@components/data/csvMapper/CsvMapperUtils';
import { useCsvMappersData } from '@components/data/csvMapper/csvMappers.data';
import {
  CsvMapperRepresentationAttributesForm_allSchemaAttributes$key,
} from '@components/data/csvMapper/representations/attributes/__generated__/CsvMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import { CsvMapperRepresentationAttributesFormFragment } from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributesForm';
import formikFieldToEditInput from '../../../../utils/FormikUtils';
import { useComputeDefaultValues } from '../../../../utils/hooks/useDefaultValues';

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
  const { schemaAttributes } = useCsvMappersData();
  const data = useFragment<CsvMapperRepresentationAttributesForm_allSchemaAttributes$key>(
    CsvMapperRepresentationAttributesFormFragment,
    schemaAttributes,
  );

  if (!data) {
    return null;
  }

  const computeDefaultValues = useComputeDefaultValues();
  const initialValues = csvMapperToFormData(
    csvMapper,
    data.csvMapperSchemaAttributes,
    computeDefaultValues,
  );

  const onSubmit: FormikConfig<CsvMapperFormData>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const formattedValues = formDataToCsvMapper(values);
    const input = formikFieldToEditInput(
      {
        ...R.omit(['id'], formattedValues),
        representations: JSON.stringify(formattedValues.representations),
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

  return <CsvMapperForm csvMapper={initialValues} onSubmit={onSubmit} />;
};

export default CsvMapperEdition;
