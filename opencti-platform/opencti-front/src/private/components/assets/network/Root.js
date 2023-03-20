/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter, Switch} from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import Network from './Network';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootNetworkSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      # ... on IntrusionSet {
      #   # ...Network_network
      #   ...NetworkEditionContainer_network
      # }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
  }
`;

// const networkQuery = graphql`
//   query RootNetworkQuery($id: String!) {
//     intrusionSet(id: $id) {
//       id
//       standard_id
//       name
//       aliases
//       x_opencti_graph_data
//       ...Network_network
//       ...NetworkKnowledge_network
//       ...FileImportViewer_entity
//       ...FileExportViewer_entity
//       ...FileExternalReferencesViewer_entity
//     }
//     connectorsForExport {
//       ...FileManager_connectorsExport
//     }
//   }
// `;

const networkQuery = graphql`
  query RootNetworkQuery($id: ID!) {
    networkAsset(id: $id) {
      id
      name
      ...Network_network
    }
  }
`;

class RootNetwork extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { networkId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: networkId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { networkId },
      },
    } = this.props;
    const link = `/defender_hq/assets/network/${networkId}/knowledge`;
    return (
      <div>
        <Route path="/defender_hq/assets/network/:networkId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'victimology',
              'attribution',
              'campaigns',
              'incidents',
              'malwares',
              'attack_patterns',
              'tools',
              'vulnerabilities',
              'observables',
              'infrastructures',
              'sightings',
              'observed_data',
            ]}
          />
        </Route>
        <QueryRenderer
          query={networkQuery}
          variables={{ id: networkId }}
          render={({ error, props, retry }) => {
            if (props) {
              if (props.networkAsset) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/defender_hq/assets/network/:networkId"
                      render={(routeProps) => (
                        <Network
                          {...routeProps}
                          refreshQuery={retry}
                          network={props.networkAsset}
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

RootNetwork.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootNetwork);
