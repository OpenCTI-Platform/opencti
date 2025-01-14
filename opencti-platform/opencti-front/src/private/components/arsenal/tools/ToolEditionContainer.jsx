import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ToolEditionOverview from './ToolEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useHelper from '../../../../utils/hooks/useHelper';

const ToolEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const { handleClose, tool, open, controlledDial } = props;
  const { editContext } = tool;

  return (
    <Drawer
      title={t_i18n('Update a tool')}
      open={open}
      onClose={handleClose}
      variant={!isFABReplaced && open == null ? DrawerVariant.update : undefined}
      context={editContext}
      controlledDial={isFABReplaced ? controlledDial : undefined}
    >
      <ToolEditionOverview
        toolRef={tool}
        enableReferences={useIsEnforceReference('Tool')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const ToolEditionFragment = createFragmentContainer(ToolEditionContainer, {
  tool: graphql`
    fragment ToolEditionContainer_tool on Tool {
      id
      ...ToolEditionOverview_tool
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default ToolEditionFragment;
