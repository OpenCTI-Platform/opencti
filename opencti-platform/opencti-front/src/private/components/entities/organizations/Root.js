import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Organization from './Organization';
import OrganizationReports from './OrganizationReports';
import OrganizationKnowledge from './OrganizationKnowledge';
import OrganizationObservables from './OrganizationObservables';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import FileManager from '../../common/files/FileManager';
import OrganizationPopover from './OrganizationPopover';
import Loader from '../../../../components/Loader';
import StixObjectHistory from '../../common/stix_object/StixObjectHistory';

const subscription = graphql`
  subscription RootOrganizationSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on Organization {
        ...Organization_organization
        ...OrganizationEditionContainer_organization
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const organizationQuery = graphql`
  query RootOrganizationQuery($id: String!) {
    organization(id: $id) {
      id
      name
      alias
      ...Organization_organization
      ...OrganizationReports_organization
      ...OrganizationKnowledge_organization
      ...OrganizationObservables_organization
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootOrganization extends Component {
  componentDidMount() {
    const {
      match: {
        params: { organizationId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: organizationId },
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
        params: { organizationId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={organizationQuery}
          variables={{ id: organizationId }}
          render={({ props }) => {
            if (props && props.organization) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/entities/organizations/:organizationId"
                    render={(routeProps) => (
                      <Organization
                        {...routeProps}
                        organization={props.organization}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/organizations/:organizationId/reports"
                    render={(routeProps) => (
                      <OrganizationReports
                        {...routeProps}
                        organization={props.organization}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/organizations/:organizationId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/entities/organizations/${organizationId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/entities/organizations/:organizationId/knowledge"
                    render={(routeProps) => (
                      <OrganizationKnowledge
                        {...routeProps}
                        organization={props.organization}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/entities/organizations/:organizationId/observables"
                    render={(routeProps) => (
                      <OrganizationObservables
                        {...routeProps}
                        organization={props.organization}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/organizations/:organizationId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainEntityHeader
                          stixDomainEntity={props.organization}
                          PopoverComponent={<OrganizationPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={organizationId}
                          connectorsExport={props.connectorsForExport}
                          entity={props.organization}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/organizations/:organizationId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainEntityHeader
                          stixDomainEntity={props.organization}
                          PopoverComponent={<OrganizationPopover />}
                        />
                        <StixObjectHistory
                          {...routeProps}
                          entityId={organizationId}
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

RootOrganization.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootOrganization);
