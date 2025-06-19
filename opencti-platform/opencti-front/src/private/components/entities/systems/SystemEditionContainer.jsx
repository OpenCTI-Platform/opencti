import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import SystemEditionOverview from './SystemEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';

const SystemEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, system, open, controlledDial } = props;
  const { editContext } = system;

  return (
    <Drawer
      title={t_i18n('Update a system')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
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
