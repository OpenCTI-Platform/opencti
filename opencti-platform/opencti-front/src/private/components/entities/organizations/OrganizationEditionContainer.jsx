import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import OrganizationEditionOverview from './OrganizationEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';

const OrganizationEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, organization, open, controlledDial } = props;
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
