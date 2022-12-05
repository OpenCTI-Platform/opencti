/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  Route, Redirect, withRouter, Switch,
} from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../../relay/environment';
import EntityTask from './EntityTask';
import Loader from '../../../../../components/Loader';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { toastGenericError } from "../../../../../utils/bakedToast";

const subscription = graphql`
  subscription RootTasksSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      # ... on ThreatActor {
        # ...Device_device
        # ...DeviceEditionContainer_device
      # }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
  }
`;

const taskQuery = graphql`
  query RootTaskQuery($id: ID!) {
    oscalTask(id: $id) {
      id
      name
      description
      ...EntityTask_task
    }
  }
`;

class RootTask extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { taskId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: taskId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { taskId },
      },
    } = this.props;
    const link = `/data/entities/tasks/${taskId}/knowledge`;
    return (
      <div>
        <Route path="/data/entities/tasks/:taskId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'victimology',
              'devices',
              'network',
              'software',
              'incidents',
              'malwares',
              'attack_patterns',
              'tools',
              'vulnerabilities',
              'observables',
              'infrastructures',
              'sightings',
            ]}
          />
        </Route>
        <QueryRenderer
          query={taskQuery}
          variables={{ id: taskId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              toastGenericError('Failed to get task data');
            }
            if (props) {
              if (props.oscalTask) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/data/entities/tasks/:taskId"
                      render={(routeProps) => (
                        <EntityTask
                          {...routeProps}
                          refreshQuery={retry}
                          task={props.oscalTask}
                        />
                      )}
                    />
                </Switch>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootTask.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootTask);
