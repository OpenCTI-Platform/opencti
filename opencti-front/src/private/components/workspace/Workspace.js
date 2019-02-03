import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { DiagramEngine } from 'storm-react-diagrams';
import Drawer from '@material-ui/core/Drawer';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import EntityLabelFactory from '../../../components/graph_node/EntityLabelFactory';
import EntityLinkFactory from '../../../components/graph_node/EntityLinkFactory';
import EntityNodeFactory from '../../../components/graph_node/EntityNodeFactory';
import EntityPortFactory from '../../../components/graph_node/EntityPortFactory';
import WorkspaceHeader from './WorkspaceHeader';
import WorkspaceGraph, { workspaceGraphQuery } from './WorkspaceGraph';

const styles = theme => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    height: 75,
  },
});

class WorkspaceKnowledgeComponent extends Component {
  constructor(props) {
    super(props);
    const engine = new DiagramEngine();
    engine.installDefaultFactories();
    engine.registerPortFactory(new EntityPortFactory());
    engine.registerNodeFactory(new EntityNodeFactory());
    engine.registerLinkFactory(new EntityLinkFactory());
    engine.registerLabelFactory(new EntityLabelFactory());
    this.state = { engine };
  }

  render() {
    const { classes, workspace } = this.props;
    return (
      <div className={classes.container}>
        <Drawer anchor='bottom' variant='permanent' classes={{ paper: classes.bottomNav }}>
          <div> &nbsp; </div>
        </Drawer>
        <WorkspaceHeader workspace={workspace}/>
        <QueryRenderer
          query={workspaceGraphQuery}
          variables={{ id: workspace.id }}
          render={({ props }) => {
            if (props && props.workspace) {
              return <WorkspaceGraph workspace={props.workspace} engine={this.state.engine}/>;
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
