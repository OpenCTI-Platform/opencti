/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {  Route, withRouter, Switch } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import Device from './Device';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootDeviceSubscription($id: ID!) {
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

const deviceQuery = graphql`
  query RootDeviceQuery($id: ID!) {
    hardwareAsset(id: $id) {
      id
      name
      ...Device_device
    }
  }
`;

class RootDevice extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { deviceId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: deviceId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { deviceId },
      },
    } = this.props;
    const link = `/defender HQ/assets/devices/${deviceId}/knowledge`;
    return (
      <div>
        <Route path="/defender HQ/assets/devices/:deviceId/knowledge">
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
          query={deviceQuery}
          variables={{ id: deviceId }}
          render={({ props, retry }) => {
            if (props) {
              if (props.hardwareAsset) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/defender HQ/assets/devices/:deviceId"
                      render={(routeProps) => (
                        <Device
                          {...routeProps}
                          refreshQuery={retry}
                          device={props.hardwareAsset}
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

RootDevice.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootDevice);
