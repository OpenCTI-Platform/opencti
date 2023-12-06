import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ToolEditionOverview from './ToolEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import ToolDelete from './ToolDelete';

const ToolEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, tool, open, controlledDial } = props;
  const { editContext } = tool;

  return (
    <Drawer
      title={t_i18n('Update a tool')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <>
        <ToolEditionOverview
          tool={tool}
          enableReferences={useIsEnforceReference('Tool')}
          context={editContext}
          handleClose={handleClose}
        />
        {!useIsEnforceReference('Tool')
          && <ToolDelete id={tool.id} />
        }
      </>
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
