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
import Risk from './Risk';
import RiskDeletion from './RiskDeletion';
import RiskKnowledge from './RiskKnowledge';
import Loader from '../../../../components/Loader';
import FileManager from '../../common/files/FileManager';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import RiskPopover from './RiskPopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixDomainObjectIndicators from '../../observations/indicators/StixDomainObjectIndicators';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import Remediation from './Remediation';

const subscription = graphql`
  subscription RootRiskSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on ThreatActor {
        ...Risk_risk
        ...RiskEditionContainer_risk
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
  }
`;

const riskQuery = graphql`
  query RootRiskQuery($id: String!) {
    threatActor(id: $id) {
      id
      standard_id
      name
      aliases
      x_opencti_graph_data
      ...Risk_risk
      ...RiskKnowledge_risk
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

const riskDarkLightQuery = graphql`
  query RootRiskDarkLightQuery($id: ID!) {
    risk(id: $id) {
      id
      remediations {
        edges {
          node {
            name
            description
          }
        }
      }
      priority
      deadline
      risk_status
      impacted_control_id
      risk_log {
        edges {
          node {
            related_responses {
              edges {
                node {
                  lifecycle
                }
              }
            }
          }
        }
      }
      remediations {
        edges {
          node {
            response_type
          }
        }
      } 
    }
  }
`;

class RootRisk extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { riskId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: riskId },
    });
    this.state = {
      displayEdit: false,
    };
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
  }

  handleOpenNewCreation() {
    this.props.history.push({
      pathname: '/dashboard/risk-assessment/risks',
      openNewCreation: true,
    });
  }

  render() {
    const {
      me,
      match: {
        params: { riskId },
      },
    } = this.props;
    const link = `/dashboard/risk-assessment/risks/${riskId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/risk-assessment/risks/:riskId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'victimology',
              'risks',
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
        <QR
          environment={QueryRendererDarkLight}
          query={riskDarkLightQuery}
          variables={{ id: riskId }}
          render={({ error, props }) => {
            if (props) {
              console.log('RiskData', props);
              if (props.risk) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/risk-assessment/risks/:riskId"
                      render={(routeProps) => (
                        <Risk
                          {...routeProps}
                          risk={props.risk}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/risk-assessment/risks/:riskId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <CyioDomainObjectHeader
                            cyioDomainObject={props.risk}
                            // history={history}
                            PopoverComponent={<RiskPopover />}
                            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
                            handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
                            OperationsComponent={<RiskDeletion />}
                          />
                          {/* <FileManager
                            {...routeProps}
                            id={threatActorId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.threatActor}
                          /> */}
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/risk-assessment/risks/:riskId/remediation"
                      render={(routeProps) => (
                        <React.Fragment>
                          <CyioDomainObjectHeader
                            cyioDomainObject={props.risk}
                            // history={history}
                            PopoverComponent={<RiskPopover />}
                            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
                            handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
                            OperationsComponent={<RiskDeletion />}
                          />
                          <Remediation
                            {...routeProps}
                            risk={props.risk}
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
        {/* <QueryRenderer
          query={riskQuery}
          variables={{ id: riskId }}
          render={({ props }) => {
            if (props) {
              if (props.threatActor) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/risk-assessment/risks/:riskId"
                      render={(routeProps) => (
                        <Risk
                          {...routeProps}
                          risk={props.threatActor}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/risk-assessment/risks/:riskId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/risk-assessment/risks/${riskId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/risk-assessment/risks/:riskId/knowledge"
                      render={(routeProps) => (
                        <RiskKnowledge
                          {...routeProps}
                          risk={props.threatActor}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/risk-assessment/risks/:riskId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <CyioDomainObjectHeader
                            stixDomainObject={props.threatActor}
                            PopoverComponent={<RiskPopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.threatActor
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/risk-assessment/risks/:riskId/indicators"
                      render={(routeProps) => (
                        <React.Fragment>
                          <CyioDomainObjectHeader
                            stixDomainObject={props.threatActor}
                            PopoverComponent={<RiskPopover />}
                            variant="noaliases"
                          />
                          <StixDomainObjectIndicators
                            {...routeProps}
                            stixDomainObjectId={riskId}
    stixDomainObjectLink={`/dashboard/risk-assessment/risks/${riskId}/indicators`}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                    path="/dashboard/risk-assessment/risks/:riskId/indicators/relations/:relationId"
                      render={(routeProps) => (
                        <StixCoreRelationship
                          entityId={riskId}
                          {...routeProps}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/risk-assessment/risks/:riskId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <CyioDomainObjectHeader
                            stixDomainObject={props.threatActor}
                            PopoverComponent={<RiskPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={riskId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.threatActor}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/risk-assessment/risks/:riskId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <CyioDomainObjectHeader
                            stixDomainObject={props.threatActor}
                            PopoverComponent={<RiskPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={riskId}
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

RootRisk.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootRisk);
