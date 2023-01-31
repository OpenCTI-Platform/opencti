import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter, Switch } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
} from '../../../../relay/environment';
import Risk from './Risk';
import Loader from '../../../../components/Loader';
import Remediations from './Remediations';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import RiskAnalysisContainer from './RiskAnalysisContainer';
import RiskTracking from './RiskTracking';
import RemediationRoot from './remediations/Root';
import TopBar from '../../nav/TopBar';

// const subscription = graphql`
//   subscription RootRiskSubscription($id: ID!) {
//     stixDomainObject(id: $id) {
//       # ... on ThreatActor {
//       #   ...Risk_risk
//       #   ...RiskEditionContainer_risk
//       # }
//       ...FileImportViewer_entity
//       ...FileExportViewer_entity
//       ...FileExternalReferencesViewer_entity
//     }
//   }
// `;

const riskQuery = graphql`
  query RootRiskQuery($id: ID!) {
    risk(id: $id) {
      id
      name
      ...Risk_risk
      ...RiskAnalysisContainer_risk
      # ...Remediations_risk
    }
  }
`;

class RootRisk extends Component {
  render() {
    const {
      me,
      match: {
        params: { riskId },
      },
    } = this.props;
    const link = `/activities/risk_assessment/risks/${riskId}/knowledge`;
    return (
      <div>
        <Route path="/activities/risk_assessment/risks/:riskId/knowledge">
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
        <TopBar me={me || null} />
        <QueryRenderer
          query={riskQuery}
          variables={{ id: riskId }}
          render={({ props, retry }) => {
            if (props) {
              if (props.risk) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/activities/risk_assessment/risks/:riskId"
                      render={(routeProps) => (
                        <Risk
                          {...routeProps}
                          refreshQuery={retry}
                          risk={props.risk}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/activities/risk_assessment/risks/:riskId/analysis"
                      render={(routeProps) => (
                        <RiskAnalysisContainer
                          {...routeProps}
                          refreshQuery={retry}
                          risk={props.risk}
                          riskId={riskId}
                        />
                      )}
                    />
                    {/* <Route
                      exact
                      path="/activities/risk_assessment/risks/:riskId/remediation"
                      render={(routeProps) => (
                          <Remediations
                            {...routeProps}
                            risk={props.risk}
                          />
                      )}
                    /> */}
                    <Route
                      exact
                      path="/activities/risk_assessment/risks/:riskId/remediation"
                      render={(routeProps) => (
                        <Remediations
                          {...routeProps}
                          refreshQuery={retry}
                          remediation={props.risk}
                          riskId={props.risk.id}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/activities/risk_assessment/risks/:riskId/remediation/:remediationId"
                      render={(routeProps) => (
                        <RemediationRoot
                          {...routeProps}
                          risk={props.risk}
                          riskId={props.risk.id}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/activities/risk_assessment/risks/:riskId/tracking"
                      render={(routeProps) => (
                        <RiskTracking
                          {...routeProps}
                          risk={props.risk}
                          riskId={props.risk.id}
                        />
                      )}
                    />
                    {/* <Route
                      path="/activities/risk_assessment/risks/:riskId/remediation"
                      render={(routeProps) => (
                        <RiskKnowledge
                          {...routeProps}
                          risk={props.threatActor}
                        />
                      )}
                    /> */}
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
                      path="/activities/risk_assessment/risks/:riskId"
                      render={(routeProps) => (
                        <Risk
                          {...routeProps}
                          risk={props.threatActor}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/activities/risk_assessment/risks/:riskId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/activities/risk_assessment/risks/${riskId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/activities/risk_assessment/risks/:riskId/knowledge"
                      render={(routeProps) => (
                        <RiskKnowledge
                          {...routeProps}
                          risk={props.threatActor}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/activities/risk_assessment/risks/:riskId/analysis"
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
                      path="/activities/risk_assessment/risks/:riskId/indicators"
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
    stixDomainObjectLink={`/activities/risk_assessment/risks/${riskId}/indicators`}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                    path="/activities/risk_assessment/risks/:riskId/indicators
                    /relations/:relationId"
                      render={(routeProps) => (
                        <StixCoreRelationship
                          entityId={riskId}
                          {...routeProps}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/activities/risk_assessment/risks/:riskId/files"
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
                      path="/activities/risk_assessment/risks/:riskId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <CyioDomainObjectHeader
                            stixDomainObject={props.threatActor}
                            PopoverComponent={<RiskPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            cyioCoreObjectId={riskId}
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
