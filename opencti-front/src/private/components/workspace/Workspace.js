import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import WorkspaceHeader from './WorkspaceHeader';
import WorkspaceGraph, { workspaceGraphQuery } from './WorkspaceGraph';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
});

class WorkspaceKnowledgeComponent extends Component {
  render() {
    const { classes, workspace } = this.props;
    return (
      <div className={classes.container}>
        <WorkspaceHeader workspace={workspace}/>
        <QueryRenderer
          query={workspaceGraphQuery}
          variables={{ id: workspace.id }}
          render={({ props }) => {
            if (props && props.workspace) {
              return <WorkspaceGraph workspace={props.workspace}/>;
            }
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

WorkspaceKnowledgeComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Workspace = createFragmentContainer(WorkspaceKnowledgeComponent, {
  workspace: graphql`
      fragment Workspace_workspace on Workspace {
          id
          ...WorkspaceHeader_workspace
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Workspace);
