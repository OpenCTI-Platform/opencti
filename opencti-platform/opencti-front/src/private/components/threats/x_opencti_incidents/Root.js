import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Incident from './Incident';
import IncidentReports from './IncidentReports';
import IncidentKnowledge from './IncidentKnowledge';
import IncidentObservables from './IncidentObservables';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import IncidentPopover from './IncidentPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_object/StixCoreObjectHistory';

const subscription = graphql`
  subscription RootIncidentSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Incident {
        ...Incident_incident
        ...IncidentEditionContainer_incident
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const incidentQuery = graphql`
  query RootIncidentQuery($id: String!) {
    incident(id: $id) {
      id
      name
      aliases
      ...Incident_incident
      ...IncidentReports_incident
      ...IncidentKnowledge_incident
      ...IncidentObservables_incident
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
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
                    path="/dashboard/threats/incidents/:incidentId"
                    render={(routeProps) => (
                      <Incident {...routeProps} incident={props.incident} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/incidents/:incidentId/reports"
                    render={(routeProps) => (
                      <IncidentReports
                        {...routeProps}
                        incident={props.incident}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/incidents/:incidentId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/threats/incidents/${incidentId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/threats/incidents/:incidentId/knowledge"
                    render={(routeProps) => (
                      <IncidentKnowledge
                        {...routeProps}
                        incident={props.incident}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/threats/incidents/:incidentId/observables"
                    render={(routeProps) => (
                      <IncidentObservables
                        {...routeProps}
                        incident={props.incident}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/incidents/:incidentId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.incident}
                          PopoverComponent={<IncidentPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={incidentId}
                          connectorsExport={props.connectorsForExport}
                          entity={props.incident}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/incidents/:incidentId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.incident}
                          PopoverComponent={<IncidentPopover />}
                        />
                        <StixCoreObjectHistory
                          {...routeProps}
                          entityId={incidentId}
                        />
                      </React.Fragment>
                    )}
                  />
                </div>
              );
            }
            return <Loader />;
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
