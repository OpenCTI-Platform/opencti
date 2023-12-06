import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import SystemEditionOverview from './SystemEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import SystemDelete from './SystemDelete';

const SystemEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, system, open, controlledDial } = props;
  const { editContext } = system;

  return (
    <Drawer
      title={t_i18n('Update a system')}
      open={open}
      onClose={handleClose}
      variant={open == null && controlledDial === undefined
        ? DrawerVariant.update
        : undefined}
      context={editContext}
      controlledDial={controlledDial}
    >
      <>
        <SystemEditionOverview
          system={system}
          enableReferences={useIsEnforceReference('System')}
          context={editContext}
          handleClose={handleClose}
        />
        {!useIsEnforceReference('System')
          && <SystemDelete id={system.id} />
        }
      </>
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
