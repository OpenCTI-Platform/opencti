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
import EntityLocation from './EntityLocation';
import Loader from '../../../../../components/Loader';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { toastGenericError } from "../../../../../utils/bakedToast";

const subscription = graphql`
  subscription RootLocationSubscription($id: ID!) {
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

const locationQuery = graphql`
  query RootLocationQuery($id: ID!) {
    oscalLocation(id: $id) {
      id
      name
      ...EntityLocation_location
    }
  }
`;

class RootLocation extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { locationId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: locationId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { locationId },
      },
    } = this.props;
    const link = `/data/entities/locations/${locationId}/knowledge`;
    return (
      <div>
        <Route path="/data/entities/locations/:locationId/knowledge">
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
          query={locationQuery}
          variables={{ id: locationId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              toastGenericError('Failed to get location data');
            }
            if (props) {
              if (props.oscalLocation) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/data/entities/locations/:locationId"
                      render={(routeProps) => (
                        <EntityLocation
                          {...routeProps}
                          refreshQuery={retry}
                          location={props.oscalLocation}
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

RootLocation.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootLocation);
