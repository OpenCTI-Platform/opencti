import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import { propOr } from 'ramda';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Organization from './Organization';
import OrganizationKnowledge from './OrganizationKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import OrganizationPopover from './OrganizationPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import OrganizationAnalysis from './OrganizationAnalysis';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumps';

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
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const organizationQuery = graphql`
  query RootOrganizationQuery($id: String!) {
    organization(id: $id) {
      id
      entity_type
      name
      x_opencti_aliases
      ...Organization_organization
      ...OrganizationKnowledge_organization
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
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
    const LOCAL_STORAGE_KEY = `organization-${organizationId}`;
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      LOCAL_STORAGE_KEY,
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
    const LOCAL_STORAGE_KEY = `organization-${organizationId}`;
    saveViewParameters(
      this.props.history,
      this.props.location,
      LOCAL_STORAGE_KEY,
      this.state,
    );
  }

  handleChangeViewAs(event) {
    this.setState({ viewAs: event.target.value }, () => this.saveView());
  }

  render() {
    const {
      t,
      location,
      match: {
        params: { organizationId },
      },
    } = this.props;
    const { viewAs } = this.state;
    const link = `/dashboard/entities/organizations/${organizationId}/knowledge`;
    return (
      <>
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
                'threats',
                'threat_actors',
                'intrusion_sets',
                'campaigns',
                'incidents',
                'malwares',
                'attack_patterns',
                'tools',
                'vulnerabilities',
                'observables',
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
                const { organization } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/entities/organizations/${organization.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Entities') },
                      { label: t('Organizations'), link: '/dashboard/entities/organizations' },
                      { label: organization.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Organization"
                      disableSharing={true}
                      stixDomainObject={organization}
                      isOpenctiAlias={true}
                      enableQuickSubscription={true}
                      PopoverComponent={<OrganizationPopover />}
                      onViewAs={this.handleChangeViewAs.bind(this)}
                      viewAs={viewAs}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={
                          location.pathname.includes(
                            `/dashboard/entities/organizations/${organization.id}/knowledge`,
                          )
                            ? `/dashboard/entities/organizations/${organization.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/organizations/${organization.id}`}
                          value={`/dashboard/entities/organizations/${organization.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/organizations/${organization.id}/knowledge`}
                          value={`/dashboard/entities/organizations/${organization.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/organizations/${organization.id}/analyses`}
                          value={`/dashboard/entities/organizations/${organization.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/organizations/${organization.id}/sightings`}
                          value={`/dashboard/entities/organizations/${organization.id}/sightings`}
                          label={t('Sightings')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/organizations/${organization.id}/files`}
                          value={`/dashboard/entities/organizations/${organization.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/organizations/${organization.id}/history`}
                          value={`/dashboard/entities/organizations/${organization.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/entities/organizations/:organizationId"
                        render={(routeProps) => (
                          <Organization
                            {...routeProps}
                            organization={props.organization}
                            viewAs={viewAs}
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
                            organization={organization}
                            viewAs={viewAs}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/organizations/:organizationId/analyses"
                        render={(routeProps) => (
                          <OrganizationAnalysis
                            {...routeProps}
                            organization={organization}
                            viewAs={viewAs}
                            onViewAs={this.handleChangeViewAs.bind(this)}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/organizations/:organizationId/sightings"
                        render={(routeProps) => (
                          <EntityStixSightingRelationships
                            entityId={organization.id}
                            entityLink={link}
                            noPadding={true}
                            isTo={true}
                            {...routeProps}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/organizations/:organizationId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={organizationId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.organization}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/organizations/:organizationId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={organizationId}
                          />
                        )}
                      />
                    </Switch>
                  </div>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </>
    );
  }
}

RootOrganization.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootOrganization);
