import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import inject18n from '../../../components/i18n';
import WorkspaceEditionOverview from './WorkspaceEditionOverview';
import Drawer from '../common/drawer/Drawer';

class WorkspaceEditionContainer extends Component {
  render() {
    const { t, handleClose, workspace, open } = this.props;
    const { editContext } = workspace;
    return (
      <Drawer
        title={t('Update a workspace')}
        open={open}
        onClose={handleClose}
        context={editContext}
      >
        <WorkspaceEditionOverview
          workspace={this.props.workspace}
          context={editContext}
        />
      </Drawer>
    );
  }
}

WorkspaceEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  workspace: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
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

export default compose(
  inject18n,
)(WorkspaceEditionFragment);
