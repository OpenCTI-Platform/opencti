/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import DataSourceEditionOverview from './DataSourceEditionOverview';
import { DataSourceEditionContainerQuery } from './__generated__/DataSourceEditionContainerQuery.graphql';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import DataSourceDelete from './DataSourceDelete';

export const dataSourceEditionQuery = graphql`
  query DataSourceEditionContainerQuery($id: String!) {
    dataSource(id: $id) {
      id
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
  controlledDial: (({ onOpen, onClose }: {
    onOpen: () => void;
    onClose: () => void;
  }) => React.ReactElement<any, string | React.JSXElementConstructor<any>>) | undefined
  open?: boolean
}

const DataSourceEditionContainer: FunctionComponent<DataSourceEditionContainerProps> = ({
  handleClose,
  queryRef,
  controlledDial,
  open,
}) => {
  const { t_i18n } = useFormatter();

  const { dataSource } = usePreloadedQuery(dataSourceEditionQuery, queryRef);

  if (dataSource) {
    return (
      <Drawer
        title={t_i18n('Update a data source')}
        context={dataSource.editContext}
        onClose={handleClose}
        open={open}
        controlledDial={controlledDial}
      >
        {({ onClose }) => (<>
          <DataSourceEditionOverview
            data={dataSource}
            enableReferences={useIsEnforceReference('Data-Source')}
            context={dataSource.editContext}
            handleClose={onClose}
          />
          {!useIsEnforceReference('Data-Source')
            && <DataSourceDelete id={dataSource.id} />
          }
        </>)}
      </Drawer>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default DataSourceEditionContainer;
