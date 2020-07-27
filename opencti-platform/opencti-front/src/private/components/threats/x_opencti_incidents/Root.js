import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import XOpenctiIncident from './XOpenctiIncident';
import XOpenctiIncidentReports from './XOpenctiIncidentReports';
import XOpenctiIncidentKnowledge from './XOpenctiIncidentKnowledge';
import XOpenctiIncidentObservables from './XOpenctiIncidentObservables';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import XOpenctiIncidentPopover from './XOpenctiIncidentPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';

const subscription = graphql`
  subscription RootXOpenctiIncidentSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on XOpenctiIncident {
        ...XOpenctiIncident_xOpenctiIncident
        ...XOpenctiIncidentEditionContainer_xOpenctiIncident
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const xOpenctiIncidentQuery = graphql`
  query RootXOpenctiIncidentQuery($id: String!) {
    xOpenctiIncident(id: $id) {
      id
      name
      aliases
      ...XOpenctiIncident_xOpenctiIncident
      ...XOpenctiIncidentReports_xOpenctiIncident
      ...XOpenctiIncidentKnowledge_xOpenctiIncident
      ...XOpenctiIncidentObservables_xOpenctiIncident
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootXOpenctiIncident extends Component {
  componentDidMount() {
    const {
      match: {
        params: { xOpenctiIncidentId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: xOpenctiIncidentId },
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
        params: { xOpenctiIncidentId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={xOpenctiIncidentQuery}
          variables={{ id: xOpenctiIncidentId }}
          render={({ props }) => {
            if (props && props.xOpenctiIncident) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId"
                    render={(routeProps) => (
                      <XOpenctiIncident
                        {...routeProps}
                        xOpenctiIncident={props.xOpenctiIncident}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/reports"
                    render={(routeProps) => (
                      <XOpenctiIncidentReports
                        {...routeProps}
                        xOpenctiIncident={props.xOpenctiIncident}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/threats/xOpenctiIncidents/${xOpenctiIncidentId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/knowledge"
                    render={(routeProps) => (
                      <XOpenctiIncidentKnowledge
                        {...routeProps}
                        xOpenctiIncident={props.xOpenctiIncident}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/observables"
                    render={(routeProps) => (
                      <XOpenctiIncidentObservables
                        {...routeProps}
                        xOpenctiIncident={props.xOpenctiIncident}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.xOpenctiIncident}
                          PopoverComponent={<XOpenctiIncidentPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={xOpenctiIncidentId}
                          connectorsExport={props.connectorsForExport}
                          entity={props.xOpenctiIncident}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.xOpenctiIncident}
                          PopoverComponent={<XOpenctiIncidentPopover />}
                        />
                        <StixCoreObjectHistory
                          {...routeProps}
                          entityId={xOpenctiIncidentId}
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

RootXOpenctiIncident.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootXOpenctiIncident);
