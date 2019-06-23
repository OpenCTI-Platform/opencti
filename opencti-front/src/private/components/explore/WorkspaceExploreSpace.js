import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, map, values, assoc, dissoc, indexBy, prop,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { WidthProvider, Responsive } from 'react-grid-layout';
import { withStyles } from '@material-ui/core/styles';
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

const ResponsiveReactGridLayout = WidthProvider(Responsive);

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

  decodeWorkspaceData() {
    const { workspace } = this.props;
    let workspaceData = {};
    if (workspace.workspace_data && workspace.workspace_data.length > 0) {
      workspaceData = JSON.parse(
        Buffer.from(workspace.workspace_data, 'base64').toString('ascii'),
      );
    }
    return workspaceData;
  }

  handleActionWidget(newValues) {
    const workspaceData = this.decodeWorkspaceData();
    const finalWorkspaceData = assoc(
      newValues.id,
      assoc(
        'layout',
        {
          i: newValues.id,
          x: 0,
          y: 0,
          w: 4,
          h: 4,
          minW: 2,
          minH: 2,
        },
        newValues,
      ),
      workspaceData,
    );
    this.saveWorkspace(finalWorkspaceData);
  }

  handleDeleteWidget(widgetId) {
    const workspaceData = this.decodeWorkspaceData();
    const finalWorkspaceData = dissoc(widgetId, workspaceData);
    this.saveWorkspace(finalWorkspaceData);
  }

  onLayoutChange(layouts) {
    const workspaceData = this.decodeWorkspaceData();
    const layoutsObject = indexBy(prop('i'), layouts);
    const finalWorkspaceData = map(n => assoc('layout', layoutsObject[n.id], n), workspaceData);
    this.saveWorkspace(finalWorkspaceData);
  }

  render() {
    const { classes, workspace } = this.props;
    let workspaceData = {};
    if (workspace.workspace_data && workspace.workspace_data.length > 0) {
      workspaceData = JSON.parse(
        Buffer.from(workspace.workspace_data, 'base64').toString('ascii'),
      );
    }
    return (
      <div className={classes.container}>
        <ResponsiveReactGridLayout
          className="layout"
          cols={{
            lg: 12,
            md: 10,
            sm: 6,
            xs: 4,
            xxs: 2,
          }}
          rowHeight={100}
          onLayoutChange={this.onLayoutChange.bind(this)}
        >
          {map((widget) => {
            switch (widget.widget) {
              case 'VictimologyDistribution':
                return (
                  <div key={widget.id} data-grid={widget.layout}>
                    <VictimologyDistribution
                      configuration={widget}
                      onUpdate={this.handleActionWidget.bind(this)}
                      onDelete={this.handleDeleteWidget.bind(this)}
                    />
                  </div>
                );
              case 'CampaignsTimeseries':
                return (
                  <div key={widget.id} data-grid={widget.layout}>
                    <CampaignsTimeseries
                      configuration={widget}
                      onUpdate={this.handleActionWidget.bind(this)}
                      onDelete={this.handleDeleteWidget.bind(this)}
                    />
                  </div>
                );
              default:
                return <div />;
            }
          }, values(workspaceData))}
        </ResponsiveReactGridLayout>
        <ExploreAddWidget onAdd={this.handleActionWidget.bind(this)} />
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
