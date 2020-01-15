import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import WorkspaceHeader from '../workspaces/WorkspaceHeader';
import WorkspaceExploreSpace from './WorkspaceExploreSpace';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
});

class WorkspaceExploreComponent extends Component {
  render() {
    const { classes, workspace } = this.props;
    return (
      <div className={classes.container}>
        <WorkspaceHeader workspace={workspace} />
        <WorkspaceExploreSpace workspace={workspace} />
      </div>
    );
  }
}

WorkspaceExploreComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const WorkspaceExplore = createFragmentContainer(WorkspaceExploreComponent, {
  workspace: graphql`
    fragment WorkspaceExplore_workspace on Workspace {
      id
      ...WorkspaceHeader_workspace
      ...WorkspaceExploreSpace_workspace
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(WorkspaceExplore);
