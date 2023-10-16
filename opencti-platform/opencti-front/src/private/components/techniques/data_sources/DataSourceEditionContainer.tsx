import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import DataSourceEditionOverview from './DataSourceEditionOverview';
import { DataSourceEditionContainerQuery } from './__generated__/DataSourceEditionContainerQuery.graphql';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

export const dataSourceEditionQuery = graphql`
  query DataSourceEditionContainerQuery($id: String!) {
    dataSource(id: $id) {
      ...DataSourceEditionOverview_dataSource
      editContext {
        name
        focusOn
      }
    }
  }
`;

interface DataSourceEditionContainerProps {
  handleClose: () => void
  queryRef: PreloadedQuery<DataSourceEditionContainerQuery>
  open?: boolean
}

const DataSourceEditionContainer: FunctionComponent<DataSourceEditionContainerProps> = ({ handleClose, queryRef, open }) => {
  const { t } = useFormatter();

  const { dataSource } = usePreloadedQuery(dataSourceEditionQuery, queryRef);

  if (dataSource) {
    return (
      <Drawer
        title={t('Update a data source')}
        variant={open == null ? DrawerVariant.update : undefined}
        context={dataSource.editContext}
        onClose={handleClose}
        open={open}
      >
        {({ onClose }) => (
          <DataSourceEditionOverview
            data={dataSource}
            enableReferences={useIsEnforceReference('Data-Source')}
            context={dataSource.editContext}
            handleClose={onClose}
          />
        )}
      </Drawer>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default DataSourceEditionContainer;
