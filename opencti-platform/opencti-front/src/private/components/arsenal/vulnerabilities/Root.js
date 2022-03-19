import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Vulnerability from './Vulnerability';
import VulnerabilityKnowledge from './VulnerabilityKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import VulnerabilityPopover from './VulnerabilityPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixDomainObjectIndicators from '../../observations/indicators/StixDomainObjectIndicators';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootVulnerabilitySubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Vulnerability {
        ...Vulnerability_vulnerability
        ...VulnerabilityEditionContainer_vulnerability
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
  }
`;

const vulnerabilityQuery = graphql`
  query RootVulnerabilityQuery($id: String!) {
    vulnerability(id: $id) {
      id
      standard_id
      name
      x_opencti_graph_data
      ...Vulnerability_vulnerability
      ...VulnerabilityReports_vulnerability
      ...VulnerabilityKnowledge_vulnerability
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    settings {
      platform_enable_reference
    }
  }
`;

class RootVulnerability extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { vulnerabilityId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: vulnerabilityId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { vulnerabilityId },
      },
    } = this.props;
    const link = `/dashboard/arsenal/vulnerabilities/${vulnerabilityId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'threat_actors',
              'intrusion_sets',
              'campaigns',
              'incidents',
              'malwares',
              'tools',
              'attack_patterns',
              'observables',
              'sightings',
            ]}
          />
        </Route>
        <QueryRenderer
          query={vulnerabilityQuery}
          variables={{ id: vulnerabilityId }}
          render={({ props }) => {
            if (props) {
              if (props.vulnerability) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId"
                      render={(routeProps) => (
                        <Vulnerability
                          {...routeProps}
                          vulnerability={props.vulnerability}
                          enableReferences={props.settings.platform_enable_reference?.includes(
                            'Vulnerability',
                          )}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/arsenal/vulnerabilities/${vulnerabilityId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/knowledge"
                      render={(routeProps) => (
                        <VulnerabilityKnowledge
                          {...routeProps}
                          vulnerability={props.vulnerability}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.vulnerability}
                            PopoverComponent={<VulnerabilityPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Vulnerability',
                            )}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.vulnerability
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/indicators"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.vulnerability}
                            PopoverComponent={<VulnerabilityPopover />}
                            variant="noaliases"
                          />
                          <StixDomainObjectIndicators
                            {...routeProps}
                            stixDomainObjectId={vulnerabilityId}
                            stixDomainObjectLink={`/dashboard/arsenal/vulnerabilities/${vulnerabilityId}/indicators`}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.vulnerability}
                            PopoverComponent={<VulnerabilityPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Vulnerability',
                            )}
                          />
                          <FileManager
                            {...routeProps}
                            id={vulnerabilityId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.vulnerability}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.vulnerability}
                            PopoverComponent={<VulnerabilityPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Vulnerability',
                            )}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={vulnerabilityId}
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
        />
      </div>
    );
  }
}

RootVulnerability.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootVulnerability);
