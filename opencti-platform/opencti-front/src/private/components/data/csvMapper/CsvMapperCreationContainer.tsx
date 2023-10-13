import React, { FunctionComponent } from 'react';
import {
  CsvMapperLinesPaginationQuery$variables,
} from '@components/data/csvMapper/__generated__/CsvMapperLinesPaginationQuery.graphql';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import CsvMapperCreation from '@components/data/csvMapper/CsvMapperCreation';
import { useFormatter } from '../../../../components/i18n';

interface CsvMapperCreationProps {
  paginationOptions: CsvMapperLinesPaginationQuery$variables;
}

const CsvMapperCreationContainer: FunctionComponent<CsvMapperCreationProps> = ({
  paginationOptions,
}) => {
  const { t } = useFormatter();

  return (
    <Drawer
      title={t('Create a csv mapper')}
      variant={DrawerVariant.createWithPanel}
    >
      <CsvMapperCreation paginationOptions={paginationOptions}/>
    </Drawer>
  );
};

export default CsvMapperCreationContainer;
