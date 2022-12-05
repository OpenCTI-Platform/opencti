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
import EntityResponsibleParty from './EntityResponsibleParty';
import Loader from '../../../../../components/Loader';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import { toastGenericError } from "../../../../../utils/bakedToast";
import StixCoreObjectKnowledgeBar from '../../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootResponsiblePartySubscription($id: ID!) {
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

const responsiblePartyQuery = graphql`
  query RootResponsiblePartyQuery($id: ID!) {
    oscalResponsibleParty(id: $id) {
      id
      ...EntityResponsibleParty_responsibleParty
    }
  }
`;

class RootResponsibleParty extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { respPartyId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: respPartyId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { respPartyId },
      },
    } = this.props;
    const link = `/data/entities/responsible_parties/${respPartyId}/knowledge`;
    return (
      <div>
        <Route path="/data/entities/responsible_parties/:respPartyId/knowledge">
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
          query={responsiblePartyQuery}
          variables={{ id: respPartyId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              toastGenericError('Failed to get Responsible Party data');
            }
            if (props) {
              if (props.oscalResponsibleParty) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/data/entities/responsible_parties/:respPartyId"
                      render={(routeProps) => (
                        <EntityResponsibleParty
                          {...routeProps}
                          refreshQuery={retry}
                          responsibleParty={props.oscalResponsibleParty}
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

RootResponsibleParty.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootResponsibleParty);
