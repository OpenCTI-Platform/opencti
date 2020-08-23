import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import XOpenCTIIncident from './XOpenCTIIncident';
import XOpenCTIIncidentReports from './XOpenCTIIncidentReports';
import XOpenCTIIncidentKnowledge from './XOpenCTIIncidentKnowledge';
import XOpenCTIIncidentObservables from './XOpenCTIIncidentObservables';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import XOpenCTIIncidentPopover from './XOpenCTIIncidentPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';

const subscription = graphql`
  subscription RootXOpenCTIIncidentSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on XOpenCTIIncident {
        ...XOpenCTIIncident_xOpenCTIIncident
        ...XOpenCTIIncidentEditionContainer_xOpenCTIIncident
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const XOpenCTIIncidentQuery = graphql`
  query RootXOpenCTIIncidentQuery($id: String!) {
    xOpenCTIIncident(id: $id) {
      id
      name
      aliases
      ...XOpenCTIIncident_xOpenCTIIncident
      ...XOpenCTIIncidentReports_xOpenCTIIncident
      ...XOpenCTIIncidentKnowledge_xOpenCTIIncident
      ...XOpenCTIIncidentObservables_xOpenCTIIncident
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootXOpenCTIIncident extends Component {
  componentDidMount() {
    const {
      match: {
        params: { XOpenCTIIncidentId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: XOpenCTIIncidentId },
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
          query={XOpenCTIIncidentQuery}
          variables={{ id: incidentId }}
          render={({ props }) => {
            if (props && props.xOpenCTIIncident) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/threats/incidents/:incidentId"
                    render={(routeProps) => (
                      <XOpenCTIIncident
                        {...routeProps}
                        xOpenCTIIncident={props.xOpenCTIIncident}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/incidents/:incidentId/reports"
                    render={(routeProps) => (
                      <XOpenCTIIncidentReports
                        {...routeProps}
                        xOpenCTIIncident={props.xOpenCTIIncident}
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
                      <XOpenCTIIncidentKnowledge
                        {...routeProps}
                        xOpenCTIIncident={props.xOpenCTIIncident}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/threats/incidents/:incidentId/observables"
                    render={(routeProps) => (
                      <XOpenCTIIncidentObservables
                        {...routeProps}
                        xOpenCTIIncident={props.xOpenCTIIncident}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/incidents/:incidentId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.xOpenCTIIncident}
                          PopoverComponent={<XOpenCTIIncidentPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={incidentId}
                          connectorsExport={props.connectorsForExport}
                          entity={props.xOpenCTIIncident}
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
                          stixDomainObject={props.xOpenCTIIncident}
                          PopoverComponent={<XOpenCTIIncidentPopover />}
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

RootXOpenCTIIncident.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootXOpenCTIIncident);
