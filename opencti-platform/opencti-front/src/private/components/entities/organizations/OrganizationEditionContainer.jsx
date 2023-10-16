import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import OrganizationEditionOverview from './OrganizationEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const OrganizationEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, organization, open } = props;
  const { editContext } = organization;

  return (
    <Drawer
      title={t('Update an organization')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
    >
      <OrganizationEditionOverview
        organization={organization}
        enableReferences={useIsEnforceReference('Organization')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const OrganizationEditionFragment = createFragmentContainer(
  OrganizationEditionContainer,
  {
    organization: graphql`
      fragment OrganizationEditionContainer_organization on Organization {
        id
        ...OrganizationEditionOverview_organization
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default OrganizationEditionFragment;
