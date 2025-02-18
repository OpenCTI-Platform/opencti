import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import CsvMapperCreation from '@components/data/csvMapper/CsvMapperCreation';
import { csvMappers_MappersQuery$variables } from '@components/data/csvMapper/__generated__/csvMappers_MappersQuery.graphql';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { CsvMapperEditionContainerQuery } from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerQuery.graphql';
import { csvMapperEditionContainerQuery } from '@components/data/csvMapper/CsvMapperEditionContainer';
import { CsvMappersImportQuery$data } from '@components/data/__generated__/CsvMappersImportQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

interface CsvMapperCreationProps {
  paginationOptions: csvMappers_MappersQuery$variables;
  editionQueryRef?: PreloadedQuery<CsvMapperEditionContainerQuery>,
  importedFileData?: CsvMappersImportQuery$data['csvMapperAddInputFromImport'],
  isDuplicated?: boolean;
  onClose?: () => void;
  open: boolean;
}

const CsvMapperCreationContainer: FunctionComponent<CsvMapperCreationProps> = ({
  editionQueryRef,
  importedFileData,
  onClose,
  isDuplicated,
  open,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const mappingCsv = editionQueryRef ? (usePreloadedQuery(csvMapperEditionContainerQuery, editionQueryRef)).csvMapper : null;

  return (
    <Drawer
      title={isDuplicated ? t_i18n('Duplicate a CSV mapper') : t_i18n('Create a CSV mapper')}
      open={open}
      onClose={onClose}
    >
      <CsvMapperCreation
        mappingCsv={mappingCsv}
        addInputFromImport={importedFileData}
        paginationOptions={paginationOptions}
        onClose={onClose}
        isDuplicated={isDuplicated}
      />
    </Drawer>
  );
};

export default CsvMapperCreationContainer;
