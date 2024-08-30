import React, { useMemo, Suspense, useState } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import * as R from 'ramda';
import { propOr } from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { RootOrganizationQuery } from '@components/entities/organizations/__generated__/RootOrganizationQuery.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';

import { RootOrganizationSubscription } from '@components/entities/organizations/__generated__/RootOrganizationSubscription.graphql';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat_router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Organization from './Organization';
import OrganizationKnowledge from './OrganizationKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import OrganizationPopover from './OrganizationPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import OrganizationAnalysis from './OrganizationAnalysis';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import inject18n, { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

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
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...Organization_organization
      ...OrganizationKnowledge_organization
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
      ...StixCoreObjectContent_stixCoreObject
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

type RootOrganizationProps = {
  organizationId: string;
  queryRef: PreloadedQuery<RootOrganizationQuery>;
};

const RootOrganization = ({ organizationId, queryRef }: RootOrganizationProps) => {
  const [viewAs, setViewAs] = useState(propOr('knowledge', 'viewAs', params));
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootOrganizationSubscription>>(() => ({
    subscription,
    variables: { id: organizationId },
  }), [organizationId]);

  const saveView = () => {
    const LOCAL_STORAGE_KEY = `organization-${organizationId}`;
    saveViewParameters(
      this.props.navigate,
      this.props.location,
      LOCAL_STORAGE_KEY,
      this.state,
    );
  };

  const handleChangeViewAs = (event) => {
    setViewAs(event.target.value);
    saveView();
  };

  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription<RootOrganizationSubscription>(subConfig);

  const {
    organization,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootOrganizationQuery>(organizationQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const link = `/dashboard/entities/organizations/${organizationId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, organization.id, '/dashboard/entities/organizations', viewAs === 'knowledge');
  return (
    <>
      {organization ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={viewAs === 'knowledge' && (
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
                  stixCoreObjectsDistribution={organization.stixCoreObjectsDistribution}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs variant="object" elements={[
              { label: t_i18n('Entities') },
              { label: t_i18n('Organizations'), link: '/dashboard/entities/organizations' },
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
              onViewAs={handleChangeViewAs}
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
                value={getCurrentTab(location.pathname, organization.id, '/dashboard/entities/organizations')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}`}
                  value={`/dashboard/entities/organizations/${organization.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/knowledge/overview`}
                  value={`/dashboard/entities/organizations/${organization.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/content`}
                  value={`/dashboard/entities/organizations/${organization.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/analyses`}
                  value={`/dashboard/entities/organizations/${organization.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/sightings`}
                  value={`/dashboard/entities/organizations/${organization.id}/sightings`}
                  label={t_i18n('Sightings')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/files`}
                  value={`/dashboard/entities/organizations/${organization.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/history`}
                  value={`/dashboard/entities/organizations/${organization.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <Organization
                    organization={organization}
                    viewAs={viewAs}
                  />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate
                    replace={true}
                    to={`/dashboard/entities/organizations/${organizationId}/knowledge/overview`}
                  />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div key={forceUpdate}>
                    <OrganizationKnowledge
                      organization={organization}
                      viewAs={viewAs}
                    />
                  </div>
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={organization}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <OrganizationAnalysis
                    organization={organization}
                    viewAs={viewAs}
                    onViewAs={handleChangeViewAs}
                  />
                }
              />
              <Route
                path="/sightings"
                element={
                  <EntityStixSightingRelationships
                    entityId={organization.id}
                    entityLink={link}
                    noPadding={true}
                    isTo={true}
                  />
                }
              />
              <Route
                path="/files"
                element={
                  <FileManager
                    id={organizationId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={organization}
                  />
                }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory
                    stixCoreObjectId={organizationId}
                  />
                }
              />
            </Routes>
          </div>
        </>
      ) : (
        <ErrorNotFound />
      )}
    </>
  );
};
const Root = () => {
  const { organizationId } = useParams() as { organizationId: string; };
  const queryRef = useQueryLoading<RootOrganizationQuery>(organizationQuery, {
    id: organizationId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootOrganization organizationId={organizationId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

class RootOrganization extends Component {
  constructor(props) {
    super(props);
    const {
      params: { organizationId },
    } = props;
    const LOCAL_STORAGE_KEY = `organization-${organizationId}`;
    const params = buildViewParamsFromUrlAndStorage(
      props.navigate,
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
      params: { organizationId },
    } = this.props;
    const LOCAL_STORAGE_KEY = `organization-${organizationId}`;
    saveViewParameters(
      this.props.navigate,
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
      params: { organizationId },
    } = this.props;
    const { viewAs } = this.state;
    const link = `/dashboard/entities/organizations/${organizationId}/knowledge`;

    return (
      <>
        <QueryRenderer
          query={organizationQuery}
          variables={{ id: organizationId }}
          render={({ props }) => {
            if (props) {
              if (props.organization) {
                const { organization } = props;
                const paddingRight = getPaddingRight(location.pathname, organization.id, '/dashboard/entities/organizations', viewAs === 'knowledge');
                return (
                  <>
                    <Routes>
                      <Route
                        path="/knowledge/*"
                        element={viewAs === 'knowledge' && (
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
                            stixCoreObjectsDistribution={organization.stixCoreObjectsDistribution}
                          />
                        )}
                      />
                    </Routes>
                    <div style={{ paddingRight }}>
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
                          value={getCurrentTab(location.pathname, organization.id, '/dashboard/entities/organizations')}
                        >
                          <Tab
                            component={Link}
                            to={`/dashboard/entities/organizations/${organization.id}`}
                            value={`/dashboard/entities/organizations/${organization.id}`}
                            label={t('Overview')}
                          />
                          <Tab
                            component={Link}
                            to={`/dashboard/entities/organizations/${organization.id}/knowledge/overview`}
                            value={`/dashboard/entities/organizations/${organization.id}/knowledge`}
                            label={t('Knowledge')}
                          />
                          <Tab
                            component={Link}
                            to={`/dashboard/entities/organizations/${organization.id}/content`}
                            value={`/dashboard/entities/organizations/${organization.id}/content`}
                            label={t('Content')}
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
                      <Routes>
                        <Route
                          path="/"
                          element={
                            <Organization
                              organization={props.organization}
                              viewAs={viewAs}
                            />
                        }
                        />
                        <Route
                          path="/knowledge"
                          element={
                            <Navigate
                              replace={true}
                              to={`/dashboard/entities/organizations/${organizationId}/knowledge/overview`}
                            />
                        }
                        />
                        <Route
                          path="/knowledge/*"
                          element={
                            <OrganizationKnowledge
                              organization={organization}
                              viewAs={viewAs}
                            />
                        }
                        />
                        <Route
                          path="/content/*"
                          element={
                            <StixCoreObjectContentRoot
                              stixCoreObject={organization}
                            />
                        }
                        />
                        <Route
                          path="/analyses"
                          element={
                            <OrganizationAnalysis
                              organization={organization}
                              viewAs={viewAs}
                              onViewAs={this.handleChangeViewAs.bind(this)}
                            />
                        }
                        />
                        <Route
                          path="/sightings"
                          element={
                            <EntityStixSightingRelationships
                              entityId={organization.id}
                              entityLink={link}
                              noPadding={true}
                              isTo={true}
                            />
                        }
                        />
                        <Route
                          path="/files"
                          element={
                            <FileManager
                              id={organizationId}
                              connectorsImport={props.connectorsForImport}
                              connectorsExport={props.connectorsForExport}
                              entity={props.organization}
                            />
                        }
                        />
                        <Route
                          path="/history"
                          element={
                            <StixCoreObjectHistory
                              stixCoreObjectId={organizationId}
                            />
                        }
                        />
                      </Routes>
                    </div>
                  </>
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
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootOrganization);
