import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import InfrastructureEditionOverview from './InfrastructureEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { InfrastructureEditionContainerQuery } from './__generated__/InfrastructureEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';

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
  handleClose: () => void
  queryRef: PreloadedQuery<InfrastructureEditionContainerQuery>
  open?: boolean
}

const InfrastructureEditionContainer: FunctionComponent<InfrastructureEditionContainerProps> = ({ handleClose, queryRef, open }) => {
  const { t } = useFormatter();

  const { infrastructure } = usePreloadedQuery(infrastructureEditionContainerQuery, queryRef);

  if (infrastructure) {
    return (
      <Drawer
        title={t('Update an infrastructure')}
        variant={open == null ? DrawerVariant.update : undefined}
        context={infrastructure.editContext}
        onClose={handleClose}
        open={open}
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

  return <Loader variant={LoaderVariant.inElement} />;
};

export default InfrastructureEditionContainer;
