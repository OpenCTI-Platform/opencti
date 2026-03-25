import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import DataSourceEditionOverview from './DataSourceEditionOverview';
import { DataSourceEditionContainerQuery } from './__generated__/DataSourceEditionContainerQuery.graphql';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { useEntityTypeDisplayName } from '../../../../utils/hooks/useEntityTypeDisplayName';

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
  handleClose: () => void;
  queryRef: PreloadedQuery<DataSourceEditionContainerQuery>;
  open?: boolean;
  controlledDial?: DrawerControlledDialType;
}

const DataSourceEditionContainer: FunctionComponent<DataSourceEditionContainerProps> = ({
  handleClose,
  queryRef,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const entityTypeDisplayName = useEntityTypeDisplayName();
  const { dataSource } = usePreloadedQuery(dataSourceEditionQuery, queryRef);

  if (dataSource) {
    return (
      <Drawer
        title={t_i18n('', { id: 'Update ...', values: { entity_type: entityTypeDisplayName('Data-Source') } })}
        context={dataSource.editContext}
        onClose={handleClose}
        open={open}
        controlledDial={controlledDial}
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

  return <Loader variant={LoaderVariant.inline} />;
};

export default DataSourceEditionContainer;
