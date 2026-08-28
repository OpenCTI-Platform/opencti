import React from 'react';
import PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import WorkspaceEditionOverview from './WorkspaceEditionOverview';
import Drawer from '../common/drawer/Drawer';

const WorkspaceEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { handleClose, workspace, open, type } = props;
  const { editContext } = workspace;
  return (
    <Drawer
      title={t_i18n(`Update ${type}`)}
      open={open}
      onClose={handleClose}
      context={editContext}
    >
      <WorkspaceEditionOverview
        workspace={props.workspace}
        context={editContext}
      />
    </Drawer>
  );
};

WorkspaceEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  workspace: PropTypes.object,
  theme: PropTypes.object,
  type: PropTypes.oneOf(['dashboard', 'investigation']),
};

const WorkspaceEditionFragment = createFragmentContainer(
  WorkspaceEditionContainer,
  {
    workspace: graphql`
      fragment WorkspaceEditionContainer_workspace on Workspace {
        id
        ...WorkspaceEditionOverview_workspace
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default WorkspaceEditionFragment;
