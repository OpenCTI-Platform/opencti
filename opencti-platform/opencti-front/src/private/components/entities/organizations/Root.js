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
import OrganizationKnowledge from './OrganizationKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import OrganizationPopover from './OrganizationPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

const subscription = graphql`
  subscription RootOrganizationSubscription($id: ID!) {
    stixDomainObject(id: $id) {
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
      x_opencti_aliases
      ...Organization_organization
      ...OrganizationKnowledge_organization
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
                    exact
                    path="/dashboard/entities/organizations/:organizationId/analysis"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.organization}
                          PopoverComponent={<OrganizationPopover />}
                        />
                        <StixCoreObjectOrStixCoreRelationshipContainers
                          {...routeProps}
                          stixCoreObjectOrStixCoreRelationshipId={
                            organizationId
                          }
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/organizations/:organizationId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.organization}
                          PopoverComponent={<OrganizationPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={organizationId}
                          connectorsImport={[]}
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
                        <StixDomainObjectHeader
                          stixDomainObject={props.organization}
                          PopoverComponent={<OrganizationPopover />}
                        />
                        <StixCoreObjectHistory
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
