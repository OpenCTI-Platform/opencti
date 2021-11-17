import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  Route, Redirect, withRouter, Switch,
} from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR } from 'react-relay';
import QueryRendererDarkLight from '../../../../relay/environmentDarkLight';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Device from './Device';
import DeviceKnowledge from './DeviceKnowledge';
import Loader from '../../../../components/Loader';
import FileManager from '../../common/files/FileManager';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import DevicePopover from './DevicePopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixDomainObjectIndicators from '../../observations/indicators/StixDomainObjectIndicators';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootDeviceSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on ThreatActor {
        # ...Device_device
        ...DeviceEditionContainer_device
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
  }
`;

const deviceQuery = graphql`
  query RootDeviceQuery($id: ID!) {
    computingDeviceAsset(id: $id) {
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
    const link = `/dashboard/assets/devices/${deviceId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/assets/devices/:deviceId/knowledge">
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
          render={({ error, props }) => {
            if (props) {
              if (props.computingDeviceAsset) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/assets/devices/:deviceId"
                      render={(routeProps) => (
                        <Device
                          {...routeProps}
                          device={props.computingDeviceAsset}
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
