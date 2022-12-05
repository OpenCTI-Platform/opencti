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
    cyioExternalReference(id: $id) {
      id
      source_name
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
        <QueryRenderer
          query={externalReferenceQuery}
          variables={{ id: externalReferenceId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              toastGenericError('Failed to get external reference data');
            }
            if (props) {
              if (props.cyioExternalReference) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/data/entities/external_references/:externalReferenceId"
                      render={(routeProps) => (
                        <EntityExternalReference
                          {...routeProps}
                          refreshQuery={retry}
                          externalReference={props.cyioExternalReference}
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
