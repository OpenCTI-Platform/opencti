import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import InfrastructureEditionOverview from './InfrastructureEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { InfrastructureEditionContainerQuery } from './__generated__/InfrastructureEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useEntityLabelResolver } from '../../../../utils/hooks/useEntityLabel';

export const infrastructureEditionContainerQuery = graphql`
  query InfrastructureEditionContainerQuery($id: String!) {
    infrastructure(id: $id) {
      ...InfrastructureEditionOverview_infrastructure
      editContext {
        name
        focusOn
      }
    }
  }
`;

interface InfrastructureEditionContainerProps {
  handleClose: () => void;
  queryRef: PreloadedQuery<InfrastructureEditionContainerQuery>;
  open?: boolean;
  controlledDial?: DrawerControlledDialType;
}

const InfrastructureEditionContainer: FunctionComponent<InfrastructureEditionContainerProps> = ({
  handleClose,
  queryRef,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const entityLabel = useEntityLabelResolver();
  const { infrastructure } = usePreloadedQuery(infrastructureEditionContainerQuery, queryRef);

  if (infrastructure) {
    return (
      <Drawer
        title={t_i18n('', { id: 'Update ...', values: { entity_type: entityLabel('Infrastructure') } })}
        context={infrastructure.editContext}
        onClose={handleClose}
        open={open}
        controlledDial={controlledDial}
      >
        {({ onClose }) => (
          <InfrastructureEditionOverview
            infrastructureData={infrastructure}
            enableReferences={useIsEnforceReference('Infrastructure')}
            context={infrastructure.editContext}
            handleClose={onClose}
          />
        )}
      </Drawer>
    );
  }

  return <Loader variant={LoaderVariant.inline} />;
};

export default InfrastructureEditionContainer;
