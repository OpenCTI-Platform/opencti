import React from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { OrganizationEditionContainerQuery } from '@components/entities/organizations/__generated__/OrganizationEditionContainerQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import OrganizationEditionOverview from './OrganizationEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerControlledDialType } from '../../common/drawer/Drawer';
import ErrorNotFound from '../../../../components/ErrorNotFound';

export const organizationEditionQuery = graphql`
  query OrganizationEditionContainerQuery($id: String!) {
    organization(id: $id) {
      ...OrganizationEditionOverview_organization
      editContext {
        name
        focusOn
      }
    }
  }
`;

interface OrganizationEditionContainerProps {
  queryRef: PreloadedQuery<OrganizationEditionContainerQuery>
  handleClose: () => void
  open?: boolean
  controlledDial?: DrawerControlledDialType
}

const OrganizationEditionContainer = ({
  queryRef,
  handleClose,
  controlledDial,
  open,
}: OrganizationEditionContainerProps) => {
  const { t_i18n } = useFormatter();
  const { organization } = usePreloadedQuery(organizationEditionQuery, queryRef);
  if (!organization) {
    return <ErrorNotFound />;
  }

  const { editContext } = organization;

  return (
    <Drawer
      title={t_i18n('Update an organization')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <OrganizationEditionOverview
        organizationRef={organization}
        enableReferences={useIsEnforceReference('Organization')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

export default OrganizationEditionContainer;
