import React, { FunctionComponent } from 'react';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import CsvMapperCreation from '@components/data/csvMapper/CsvMapperCreation';
import { csvMappers_MappersQuery$variables } from '@components/data/csvMapper/__generated__/csvMappers_MappersQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

interface CsvMapperCreationProps {
  paginationOptions: csvMappers_MappersQuery$variables;
}

const CsvMapperCreationContainer: FunctionComponent<CsvMapperCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Drawer
      title={t_i18n('Create a csv mapper')}
      variant={DrawerVariant.createWithPanel}
    >
      <CsvMapperCreation paginationOptions={paginationOptions} />
    </Drawer>
  );
};

export default CsvMapperCreationContainer;
