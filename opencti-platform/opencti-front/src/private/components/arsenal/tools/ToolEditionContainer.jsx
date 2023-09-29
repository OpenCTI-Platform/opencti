import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ToolEditionOverview from './ToolEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

const ToolEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, tool, open } = props;
  const { editContext } = tool;

  return (
    <Drawer
      title={t('Update a tool')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
    >
      <ToolEditionOverview
        tool={tool}
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
