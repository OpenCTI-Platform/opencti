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
import Network from './Network';
import NetworkKnowledge from './NetworkKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import NetworkPopover from './NetworkPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixDomainObjectIndicators from '../../observations/indicators/StixDomainObjectIndicators';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootNetworkSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on IntrusionSet {
        ...Network_network
        ...NetworkEditionContainer_network
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
  }
`;

const networkQuery = graphql`
  query RootNetworkQuery($id: String!) {
    intrusionSet(id: $id) {
      id
      standard_id
      name
      aliases
      x_opencti_graph_data
      ...Network_network
      ...NetworkKnowledge_network
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

const networkDarkLightQuery = graphql`
  query RootNetworkDarkLightQuery($networkAssetId: ID!) {
    networkAsset(id: $networkAssetId) {
      id
      asset_tag
      asset_type
      operational_status
      asset_id
      locations {
        description
      }
      name
      asset_id
      serial_number
      labels
      description
      release_date
      vendor_name
      operational_status
      version
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
    const link = `/dashboard/assets/network/${networkId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/assets/network/:networkId/knowledge">
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
        <QR
          environment={QueryRendererDarkLight}
          query={networkDarkLightQuery}
          variables={{ networkAssetId: networkId }}
          render={({ error, props }) => {
            console.log(`networkDarkLightQuery ${JSON.stringify(props)} OR Error: ${error}`);
            if (props) {
              if (props.networkAsset) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/assets/network/:networkId"
                      render={(routeProps) => (
                        <Network
                          {...routeProps}
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
        {/* <QueryRenderer
          query={networkQuery}
          variables={{ id: networkId }}
          render={({ props }) => {
            if (props) {
              if (props.network) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/assets/network/:networkId"
                      render={(routeProps) => (
                        <Network
                          {...routeProps}
                          network={props.network}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/network/:networkId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/assets/network/${networkId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/assets/network/:networkId/knowledge"
                      render={(routeProps) => (
                        <NetworkKnowledge
                          {...routeProps}
                          network={props.network}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/network/:networkId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.network}
                            PopoverComponent={<NetworkPopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.network
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/network/:networkId/indicators"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.network}
                            PopoverComponent={<NetworkPopover />}
                            variant="noaliases"
                          />
                          <StixDomainObjectIndicators
                            {...routeProps}
                            stixDomainObjectId={networkId}
                        stixDomainObjectLink={`/dashboard/assets/network/${networkId}/indicators`}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/network/:networkId/indicators/relations/:relationId"
                      render={(routeProps) => (
                        <StixCoreRelationship
                          entityId={networkId}
                          {...routeProps}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/network/:networkId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.network}
                            PopoverComponent={<NetworkPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={networkId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.network}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/network/:networkId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.network}
                            PopoverComponent={<NetworkPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={networkId}
                          />
                        </React.Fragment>
                      )}
                    />
                  </Switch>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        /> */}
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
