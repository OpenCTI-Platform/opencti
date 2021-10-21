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
import Software from './Software';
import SoftwareKnowledge from './SoftwareKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import SoftwarePopover from './SoftwarePopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixDomainObjectIndicators from '../../observations/indicators/StixDomainObjectIndicators';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootSoftwareSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Campaign {
        ...Software_software
        ...SoftwareEditionContainer_software
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
  }
`;

const softwareQuery = graphql`
  query RootSoftwareQuery($id: String!) {
    campaign(id: $id) {
      id
      standard_id
      name
      aliases
      x_opencti_graph_data
      ...Software_software
      ...SoftwareKnowledge_software
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

const softwareDarkLightQuery = graphql`
  query RootSoftwareDarkLightQuery($id: ID!) {
    softwareAsset(id: $id) {
      id
      name
      asset_id
      labels
      description
      locations {
        city
        country
        description
      }
      version
      vendor_name
      asset_tag
      asset_type
      serial_number
      release_date
      operational_status
      ...SoftwareDetails_software
    }
  }
`;

class RootSoftware extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { softwareId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: softwareId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { softwareId },
      },
    } = this.props;
    const link = `/dashboard/assets/software/${softwareId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/assets/software/:softwareId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'attribution',
              'victimology',
              'incidents',
              'malwares',
              'tools',
              'attack_patterns',
              'vulnerabilities',
              'observables',
              'infrastructures',
              'sightings',
            ]}
          />
        </Route>
        <QR
          environment={QueryRendererDarkLight}
          query={softwareDarkLightQuery}
          variables={{ id: softwareId }}
          render={({ error, props }) => {
            console.log(`softwareDarkLightQuery ${JSON.stringify(props)} OR Error: ${error}`);
            if (props) {
              if (props.softwareAsset) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/assets/software/:softwareId"
                      render={(routeProps) => (
                        <Software {...routeProps} software={props.softwareAsset} />
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
          query={softwareQuery}
          variables={{ id: softwareId }}
          render={({ props }) => {
            if (props) {
              if (props.software) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/assets/software/:softwareId"
                      render={(routeProps) => (
                        <Software {...routeProps} software={props.software} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/software/:softwareId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/assets/software/${softwareId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/assets/software/:softwareId/knowledge"
                      render={(routeProps) => (
                        <SoftwareKnowledge
                          {...routeProps}
                          software={props.software}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/software/:softwareId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.software}
                            PopoverComponent={<SoftwarePopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.software
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/software/:softwareId/indicators"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.software}
                            PopoverComponent={<SoftwarePopover />}
                            variant="noaliases"
                          />
                          <StixDomainObjectIndicators
                            {...routeProps}
                            stixDomainObjectId={softwareId}
                        stixDomainObjectLink={`/dashboard/assets/software/${softwareId}/indicators`}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/software/:softwareId/indicators/relations/:relationId"
                      render={(routeProps) => (
                        <StixCoreRelationship
                          entityId={softwareId}
                          {...routeProps}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/software/:softwareId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.software}
                            PopoverComponent={<SoftwarePopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={softwareId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.software}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/assets/software/:softwareId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.software}
                            PopoverComponent={<SoftwarePopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={softwareId}
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

RootSoftware.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootSoftware);
