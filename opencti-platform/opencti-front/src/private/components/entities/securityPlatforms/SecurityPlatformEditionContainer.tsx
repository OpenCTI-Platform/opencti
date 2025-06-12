import React, { FunctionComponent } from 'react';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import { createFragmentContainer, graphql } from 'react-relay';
import {
  SecurityPlatformEditionContainer_securityPlatform$data,
} from '@components/entities/securityPlatforms/__generated__/SecurityPlatformEditionContainer_securityPlatform.graphql';
import SecurityPlatformEditionOverview from '@components/entities/securityPlatforms/SecurityPlatformEditionOverview';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

interface securityPlatformContainerProps {
  handleClose: () => void;
  securityPlatform:SecurityPlatformEditionContainer_securityPlatform$data,
  controlledDial?: DrawerControlledDialType
}

const SecurityPlatformEditionContainer: FunctionComponent<securityPlatformContainerProps> = ({
  handleClose,
  securityPlatform,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { editContext } = securityPlatform;

  return (
    <Drawer
      title={t_i18n('Update a security platform')}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <SecurityPlatformEditionOverview
        securityPlatform={securityPlatform}
        enableReferences={useIsEnforceReference('SecurityPlatform')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

export default createFragmentContainer(
  SecurityPlatformEditionContainer,
  {
    securityPlatform: graphql`
      fragment SecurityPlatformEditionContainer_securityPlatform on SecurityPlatform {
        id
        ...SecurityPlatformEditionOverview_securityPlatform
        editContext {
            name
            focusOn
        }
      }
    `,
  },
);
