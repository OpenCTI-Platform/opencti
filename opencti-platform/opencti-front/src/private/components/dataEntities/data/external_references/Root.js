/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  Route, Redirect, withRouter, Switch,
} from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR } from 'react-relay';
import QueryRendererDarkLight from '../../../../../relay/environmentDarkLight';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../../relay/environment';
import TopBar from '../../../nav/TopBar';
import EntityExternalReference from './EntityExternalReference';
import Loader from '../../../../../components/Loader';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { toastGenericError } from "../../../../../utils/bakedToast";

const subscription = graphql`
  subscription RootExternalReferenceSubscription($id: ID!) {
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

const externalReferenceQuery = graphql`
  query RootExternalReferenceQuery($id: ID!) {
    oscalRole(id: $id) {
      id
      name
      ...EntityExternalReference_externalReference
    }
  }
`;

class RootExternalReference extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { externalReferenceId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: externalReferenceId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { externalReferenceId },
      },
    } = this.props;
    const link = `/data/entities/external_references/${externalReferenceId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/data/entities/external_references/:externalReferenceId/knowledge">
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
        {/* <QueryRenderer */}
        <QR
          environment={QueryRendererDarkLight}
          query={externalReferenceQuery}
          variables={{ id: externalReferenceId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              toastGenericError('Failed to get external reference data');
            }
            if (props) {
              if (props.oscalRole) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/data/entities/external_references/:externalReferenceId"
                      render={(routeProps) => (
                        <EntityExternalReference
                          {...routeProps}
                          refreshQuery={retry}
                          externalReference={props.oscalRole}
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

RootExternalReference.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootExternalReference);
