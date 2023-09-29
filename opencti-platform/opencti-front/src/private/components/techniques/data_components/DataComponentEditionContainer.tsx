import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import DataComponentEditionOverview from './DataComponentEditionOverview';
import { DataComponentEditionContainerQuery } from './__generated__/DataComponentEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

export const dataComponentEditionQuery = graphql`
  query DataComponentEditionContainerQuery($id: String!) {
    dataComponent(id: $id) {
      ...DataComponentEditionOverview_dataComponent
      editContext {
        name
        focusOn
      }
    }
  }
`;

interface DataComponentEditionContainerProps {
  queryRef: PreloadedQuery<DataComponentEditionContainerQuery>
  handleClose: () => void
  open?: boolean
}

const DataComponentEditionContainer: FunctionComponent<DataComponentEditionContainerProps> = ({ queryRef, handleClose, open }) => {
  const { t } = useFormatter();
  const { dataComponent } = usePreloadedQuery(dataComponentEditionQuery, queryRef);

  if (dataComponent) {
    return (
      <Drawer
        title={t('Update a data component')}
        variant={open == null ? DrawerVariant.update : undefined}
        context={dataComponent.editContext}
        onClose={handleClose}
        open={open}
      >
        {({ onClose }) => (
          <DataComponentEditionOverview
            data={dataComponent}
            enableReferences={useIsEnforceReference('Data-Component')}
            context={dataComponent.editContext}
            handleClose={onClose}
          />
        )}
      </Drawer>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default DataComponentEditionContainer;
