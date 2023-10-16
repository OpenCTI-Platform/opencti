import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import SystemEditionOverview from './SystemEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const SystemEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, system, open } = props;
  const { editContext } = system;

  return (
    <Drawer
      title={t('Update a system')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
    >
      <SystemEditionOverview
        system={system}
        enableReferences={useIsEnforceReference('System')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const SystemEditionFragment = createFragmentContainer(SystemEditionContainer, {
  system: graphql`
    fragment SystemEditionContainer_system on System {
      id
      ...SystemEditionOverview_system
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default SystemEditionFragment;
