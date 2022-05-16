import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import { propOr } from 'ramda';
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
import OrganizationAnalysis from './OrganizationAnalysis';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootOrganizationSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Organization {
        ...Organization_organization
        ...OrganizationEditionContainer_organization
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
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

class RootOrganization extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { organizationId },
      },
    } = props;
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-organization-${organizationId}`,
    );
    this.state = {
      viewAs: propOr('knowledge', 'viewAs', params),
    };
    this.sub = requestSubscription({
      subscription,
      variables: { id: organizationId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  saveView() {
    const {
      match: {
        params: { organizationId },
      },
    } = this.props;
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-organization-${organizationId}`,
      this.state,
    );
  }

  handleChangeViewAs(event) {
    this.setState({ viewAs: event.target.value }, () => this.saveView());
  }

  render() {
    const {
      me,
      match: {
        params: { organizationId },
      },
    } = this.props;
    const { viewAs } = this.state;
    const link = `/dashboard/entities/organizations/${organizationId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/entities/organizations/:organizationId/knowledge">
          {viewAs === 'knowledge' && (
            <StixCoreObjectKnowledgeBar
              stixCoreObjectLink={link}
              availableSections={[
                'sectors',
                'organizations',
                'individuals',
                'locations',
                'used_tools',
                'threat_actors',
                'intrusion_sets',
                'campaigns',
                'incidents',
                'malwares',
                'attack_patterns',
                'tools',
                'observables',
                'sightings',
              ]}
            />
          )}
        </Route>
        <QueryRenderer
          query={organizationQuery}
          variables={{ id: organizationId }}
          render={({ props }) => {
            if (props) {
              if (props.organization) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/entities/organizations/:organizationId"
                      render={(routeProps) => (
                        <Organization
                          {...routeProps}
                          organization={props.organization}
                          viewAs={viewAs}
                          onViewAs={this.handleChangeViewAs.bind(this)}
                          enableReferences={props.settings.platform_enable_reference?.includes(
                            'Organization',
                          )}
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
                          viewAs={viewAs}
                          onViewAs={this.handleChangeViewAs.bind(this)}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/organizations/:organizationId/analysis"
                      render={(routeProps) => (
                        <OrganizationAnalysis
                          {...routeProps}
                          organization={props.organization}
                          viewAs={viewAs}
                          onViewAs={this.handleChangeViewAs.bind(this)}
                        />
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
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Organization',
                            )}
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
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Organization',
                            )}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={organizationId}
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

RootOrganization.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootOrganization);
