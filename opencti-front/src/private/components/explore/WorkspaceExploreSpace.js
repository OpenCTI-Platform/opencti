import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, map, values, sortWith, ascend, prop,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import { commitMutation } from '../../../relay/environment';
import { workspaceMutationFieldPatch } from '../workspace/WorkspaceEditionOverview';
import ExploreAddWidget from './ExploreAddWidget';
import VictimologyDistribution from './VictimologyDistribution';
import CampaignsTimeseries from './CampaignsTimeseries';

const styles = () => ({
  container: {
    margin: 0,
    padding: 0,
  },
});

class WorkspaceExploreSpaceComponent extends Component {
  saveWorkspace(workspaceData) {
    const JSONData = JSON.stringify(workspaceData);
    commitMutation({
      mutation: workspaceMutationFieldPatch,
      variables: {
        id: this.props.workspace.id,
        input: {
          key: 'workspace_data',
          value: Buffer.from(JSONData).toString('base64'),
        },
      },
    });
  }

  onActionWidget(newValues) {
    const { workspace } = this.props;
    let workspaceData = {};
    if (workspace.workspace_data && workspace.workspace_data.length > 0) {
      workspaceData = JSON.parse(
        Buffer.from(workspace.workspace_data, 'base64').toString('ascii'),
      );
    }
    workspaceData[newValues.id] = newValues;
    this.saveWorkspace(workspaceData);
  }

  onDeleteWidget(widgetId) {
    const { workspace } = this.props;
    let workspaceData = {};
    if (workspace.workspace_data && workspace.workspace_data.length > 0) {
      workspaceData = JSON.parse(
        Buffer.from(workspace.workspace_data, 'base64').toString('ascii'),
      );
    }
    delete workspaceData[widgetId];
    this.saveWorkspace(workspaceData);
  }

  render() {
    const { classes, t, workspace } = this.props;
    let workspaceData = {};
    if (workspace.workspace_data && workspace.workspace_data.length > 0) {
      workspaceData = JSON.parse(
        Buffer.from(workspace.workspace_data, 'base64').toString('ascii'),
      );
    }
    const sort = sortWith([ascend(prop('order'))]);
    return (
      <div className={classes.container}>
        <Grid container={true} spacing={3}>
          {map((widget) => {
            switch (widget.widget) {
              case 'VictimologyDistribution':
                return (
                  <VictimologyDistribution
                    onUpdate={this.onActionWidget.bind(this)}
                    onDelete={this.onDeleteWidget.bind(this)}
                    key={widget.id}
                    configuration={widget}
                  />
                );
              case 'CampaignsTimeseries':
                return (
                  <CampaignsTimeseries
                    onUpdate={this.onActionWidget.bind(this)}
                    onDelete={this.onDeleteWidget.bind(this)}
                    key={widget.id}
                    configuration={widget}
                  />
                );
              default:
                return (
                  <Grid item={true} xs={3}>
                    <div style={{ margin: 50, textAlign: 'center' }}>
                      {t('Unknown widget')}
                    </div>
                  </Grid>
                );
            }
          }, sort(values(workspaceData)))}
        </Grid>
        <ExploreAddWidget onAdd={this.onActionWidget.bind(this)} />
      </div>
    );
  }
}

WorkspaceExploreSpaceComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const WorkspaceExploreSpace = createFragmentContainer(
  WorkspaceExploreSpaceComponent,
  {
    workspace: graphql`
      fragment WorkspaceExploreSpace_workspace on Workspace {
        id
        workspace_data
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(WorkspaceExploreSpace);
