import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer, requestSubscription } from '../../../relay/environment';
import TopBar from '../nav/TopBar';
import Incident from './Incident';
import IncidentReports from './IncidentReports';
import IncidentKnowledge from './IncidentKnowledge';
import IncidentObservables from './IncidentObservables';

const subscription = graphql`
  subscription RootIncidentSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on Incident {
        ...Incident_incident
        ...IncidentEditionContainer_incident
      }
      ...StixDomainEntityKnowledgeGraph_stixDomainEntity
    }
  }
`;

const incidentQuery = graphql`
  query RootIncidentQuery($id: String!) {
    incident(id: $id) {
      ...Incident_incident
      ...IncidentHeader_incident
      ...IncidentOverview_incident
      ...IncidentIdentity_incident
      ...IncidentReports_incident
      ...IncidentKnowledge_incident
      ...IncidentObservables_incident
    }
  }
`;

class RootIncident extends Component {
  componentDidMount() {
    const {
      match: {
        params: { incidentId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: incidentId },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { incidentId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={incidentQuery}
          variables={{ id: incidentId }}
          render={({ props }) => {
            if (props && props.incident) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/knowledge/incidents/:incidentId"
                    render={routeProps => (
                      <Incident {...routeProps} incident={props.incident} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/knowledge/incidents/:incidentId/reports"
                    render={routeProps => (
                      <IncidentReports
                        {...routeProps}
                        incident={props.incident}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/knowledge/incidents/:incidentId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/knowledge/incidents/${incidentId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/knowledge/incidents/:incidentId/knowledge"
                    render={routeProps => (
                      <IncidentKnowledge
                        {...routeProps}
                        incident={props.incident}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/knowledge/incidents/:incidentId/observables"
                    render={routeProps => (
                      <IncidentObservables
                        {...routeProps}
                        incident={props.incident}
                      />
                    )}
                  />
                </div>
              );
            }
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

RootIncident.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootIncident);
