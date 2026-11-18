import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import inject18n from '../../../components/i18n';
import WorkspaceEditionOverview from './WorkspaceEditionOverview';
import Drawer from '../common/drawer/Drawer';

class WorkspaceEditionContainer extends Component {
  render() {
    const { t, handleClose, workspace, open, type, children } = this.props;
    const { editContext } = workspace;
    return (
      <Drawer
        title={t(`Update ${type}`)}
        open={open}
        onClose={handleClose}
        context={editContext}
      >
        {/* A single child: the Drawer clones it to pass onClose, a Fragment is passed through. */}
        <>
          <WorkspaceEditionOverview
            workspace={this.props.workspace}
            context={editContext}
          />
          {children}
        </>
      </Drawer>
    );
  }
}

WorkspaceEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  workspace: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  type: PropTypes.oneOf(['dashboard', 'investigation']),
  children: PropTypes.node,
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
