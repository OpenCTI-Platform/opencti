/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import DataComponentEditionOverview from './DataComponentEditionOverview';
import { DataComponentEditionContainerQuery } from './__generated__/DataComponentEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import DataComponentDelete from './DataComponentDelete';

export const dataComponentEditionQuery = graphql`
  query DataComponentEditionContainerQuery($id: String!) {
    dataComponent(id: $id) {
      id
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
  controlledDial: (({ onOpen, onClose }: {
    onOpen: () => void;
    onClose: () => void;
  }) => React.ReactElement<any, string | React.JSXElementConstructor<any>>) | undefined
  open?: boolean
}

const DataComponentEditionContainer: FunctionComponent<DataComponentEditionContainerProps> = ({
  queryRef,
  handleClose,
  controlledDial,
  open,
}) => {
  const { t_i18n } = useFormatter();
  const { dataComponent } = usePreloadedQuery(dataComponentEditionQuery, queryRef);

  if (dataComponent) {
    return (
      <Drawer
        title={t_i18n('Update a data component')}
        context={dataComponent.editContext}
        onClose={handleClose}
        open={open}
        controlledDial={controlledDial}
      >
        {({ onClose }) => (<>
          <DataComponentEditionOverview
            data={dataComponent}
            enableReferences={useIsEnforceReference('Data-Component')}
            context={dataComponent.editContext}
            handleClose={onClose}
          />
          {!useIsEnforceReference('Data-Component')
            && <DataComponentDelete id={dataComponent.id} />
          }
        </>)}
      </Drawer>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default DataComponentEditionContainer;
