import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import InfrastructureEditionOverview from './InfrastructureEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { InfrastructureEditionContainerQuery } from './__generated__/InfrastructureEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import InfrastructureDelete from './InfrastructureDelete';

export const infrastructureEditionContainerQuery = graphql`
  query InfrastructureEditionContainerQuery($id: String!) {
    infrastructure(id: $id) {
      id
      ...InfrastructureEditionOverview_infrastructure
      editContext {
        name
        focusOn
      }
    }
  }
`;

interface InfrastructureEditionContainerProps {
  handleClose: () => void
  queryRef: PreloadedQuery<InfrastructureEditionContainerQuery>
  controlledDial?: (({ onOpen, onClose }: {
    onOpen: () => void;
    onClose: () => void;
  }) => React.ReactElement<unknown, string | React.JSXElementConstructor<unknown>>)
  open?: boolean
}

const InfrastructureEditionContainer: FunctionComponent<InfrastructureEditionContainerProps> = ({
  handleClose,
  queryRef,
  controlledDial,
  open,
}) => {
  const { t_i18n } = useFormatter();

  const { infrastructure } = usePreloadedQuery(infrastructureEditionContainerQuery, queryRef);

  if (infrastructure) {
    return (
      <Drawer
        title={t_i18n('Update an infrastructure')}
        variant={open == null && controlledDial === null
          ? DrawerVariant.update
          : undefined}
        context={infrastructure.editContext}
        onClose={handleClose}
        open={open}
        controlledDial={controlledDial}
      >
        {({ onClose }) => (<>
          <InfrastructureEditionOverview
            infrastructureData={infrastructure}
            enableReferences={useIsEnforceReference('Infrastructure')}
            context={infrastructure.editContext}
            handleClose={onClose}
          />
          {!useIsEnforceReference('Infrastructure')
            && <InfrastructureDelete id={infrastructure.id} />
          }
        </>)}
      </Drawer>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default InfrastructureEditionContainer;
