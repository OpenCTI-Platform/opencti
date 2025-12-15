import { useFragment } from 'react-relay';
import { CsvMapperFormData } from '@components/data/csvMapper/CsvMapper';
import { useCsvMappersData } from '@components/data/csvMapper/csvMappers.data';
import {
  CsvMapperRepresentationAttributesForm_allSchemaAttributes$key,
} from '../csvMapper/representations/attributes/__generated__/CsvMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import { CsvMapperRepresentationAttributesFormFragment } from '../csvMapper/representations/attributes/CsvMapperRepresentationAttributesForm';
import { CsvMapperAddInput, csvMapperToFormData } from '../csvMapper/CsvMapperUtils';
import { useComputeDefaultValues } from '../../../../utils/hooks/useDefaultValues';

export const csvFeedCsvMapperToFormData = (csvMapper: CsvMapperAddInput): CsvMapperFormData => {
  const computeDefaultValues = useComputeDefaultValues();
  const { schemaAttributes } = useCsvMappersData();
  const data = useFragment<CsvMapperRepresentationAttributesForm_allSchemaAttributes$key>(
    CsvMapperRepresentationAttributesFormFragment,
    schemaAttributes,
  ) || { csvMapperSchemaAttributes: [] };
  return csvMapperToFormData(
    csvMapper,
    data.csvMapperSchemaAttributes,
    computeDefaultValues,
  );
};
