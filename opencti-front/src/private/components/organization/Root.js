import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer, requestSubscription } from '../../../relay/environment';
import TopBar from '../nav/TopBar';
import Organization from './Organization';
import OrganizationReports from './OrganizationReports';
import OrganizationKnowledge from './OrganizationKnowledge';

const subscription = graphql`
  subscription RootOrganizationSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on Organization {
        ...Organization_organization
        ...OrganizationEditionContainer_organization
      }
    }
  }
`;

const organizationQuery = graphql`
  query RootOrganizationQuery($id: String!) {
    organization(id: $id) {
      ...Organization_organization
      ...OrganizationHeader_organization
      ...OrganizationOverview_organization
      ...OrganizationReports_organization
      ...OrganizationKnowledge_organization
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
                    path="/dashboard/catalogs/organizations/:organizationId"
                    render={routeProps => (
                      <Organization
                        {...routeProps}
                        organization={props.organization}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/catalogs/organizations/:organizationId/reports"
                    render={routeProps => (
                      <OrganizationReports
                        {...routeProps}
                        organization={props.organization}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/catalogs/organizations/:organizationId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/catalogs/organizations/${organizationId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/catalogs/organizations/:organizationId/knowledge"
                    render={routeProps => (
                      <OrganizationKnowledge
                        {...routeProps}
                        organization={props.organization}
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

RootOrganization.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootOrganization);
