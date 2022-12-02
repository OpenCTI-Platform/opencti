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
import EntityParty from './EntityParty';
import Loader from '../../../../../components/Loader';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import { toastGenericError } from "../../../../../utils/bakedToast";
import StixCoreObjectKnowledgeBar from '../../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootPartySubscription($id: ID!) {
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

const partyQuery = graphql`
  query RootPartyQuery($id: ID!) {
    oscalParty(id: $id) {
      id
      name
      ...EntityParty_party
    }
  }
`;

class RootParty extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { partyId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: partyId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { partyId },
      },
    } = this.props;
    const link = `/data/entities/parties/${partyId}/knowledge`;
    return (
      <div>
        <Route path="/data/entities/parties/:partyId/knowledge">
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
          query={partyQuery}
          variables={{ id: partyId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              return toastGenericError('Failed to get party data');
            }
            if (props) {
              if (props.oscalParty) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/data/entities/parties/:partyId"
                      render={(routeProps) => (
                        <EntityParty
                          {...routeProps}
                          refreshQuery={retry}
                          party={props.oscalParty}
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

RootParty.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootParty);
