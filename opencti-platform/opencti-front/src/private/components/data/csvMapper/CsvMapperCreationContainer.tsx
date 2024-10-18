import React, { FunctionComponent } from 'react';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import CsvMapperCreation from '@components/data/csvMapper/CsvMapperCreation';
import { csvMappers_MappersQuery$variables } from '@components/data/csvMapper/__generated__/csvMappers_MappersQuery.graphql';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { CsvMapperEditionContainerQuery } from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerQuery.graphql';
import { csvMapperEditionContainerQuery } from '@components/data/csvMapper/CsvMapperEditionContainer';
import { useFormatter } from '../../../../components/i18n';

interface CsvMapperCreationProps {
  paginationOptions: csvMappers_MappersQuery$variables;
  queryRef?: PreloadedQuery<CsvMapperEditionContainerQuery>,
  isDuplicated?: boolean;
  onClose?: () => void;
  open: boolean;
}

const CsvMapperCreationContainer: FunctionComponent<CsvMapperCreationProps> = ({
  queryRef,
  onClose,
  isDuplicated,
  open,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const mappingCsv = queryRef ? (usePreloadedQuery(csvMapperEditionContainerQuery, queryRef)).csvMapper : null;

  return (
    <Drawer
      title={isDuplicated ? t_i18n('Duplicate a CSV mapper') : t_i18n('Create a CSV mapper')}
      open={open}
      onClose={onClose}
      variant={isDuplicated ? undefined : DrawerVariant.createWithPanel}
    >
      <CsvMapperCreation
        mappingCsv={mappingCsv}
        paginationOptions={paginationOptions}
        onClose={onClose}
        isDuplicated={isDuplicated}
        open={open}
      />
    </Drawer>
  );
};

export default CsvMapperCreationContainer;
