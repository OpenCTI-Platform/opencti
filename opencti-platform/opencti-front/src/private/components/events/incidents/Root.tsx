// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Route, Routes, useParams, useLocation, Navigate } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectSimulationResult from '@components/common/stix_core_objects/StixCoreObjectSimulationResult';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import Incident from './Incident';
import IncidentKnowledge from './IncidentKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import IncidentPopover from './IncidentPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RootIncidentQuery } from './__generated__/RootIncidentQuery.graphql';
import { RootIncidentSubscription } from './__generated__/RootIncidentSubscription.graphql';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab } from '../../../../utils/utils';

const subscription = graphql`
  subscription RootIncidentSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Incident {
        ...Incident_incident
        ...IncidentEditionContainer_incident
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const incidentQuery = graphql`
  query RootIncidentQuery($id: String!) {
    incident(id: $id) {
      id
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      ...Incident_incident
      ...IncidentKnowledge_incident
      ...StixCoreObjectContent_stixCoreObject
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
  }
`;

const RootIncidentComponent = ({ queryRef }) => {
  const { incidentId } = useParams() as { incidentId: string };
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootIncidentSubscription>>(
    () => ({
      subscription,
      variables: { id: incidentId },
    }),
    [incidentId],
  );
  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription(subConfig);
  const data = usePreloadedQuery(incidentQuery, queryRef);
  const { incident, connectorsForImport, connectorsForExport } = data;
  const isOverview = location.pathname === `/dashboard/events/incidents/${incident?.id}`;
  const paddingRightValue = () => {
    if (location.pathname.includes(`/dashboard/events/incidents/${incident.id}/knowledge`)) return 200;
    if (location.pathname.includes(`/dashboard/events/incidents/${incident.id}/content`)) return 350;
    if (location.pathname.includes(`/dashboard/events/incidents/${incident.id}/content/mapping`)) return 0;
    return 0;
  };
  return (
    <>
      {incident ? (
        <div
          style={{ paddingRight: paddingRightValue() }}
        >
          <Breadcrumbs variant="object" elements={[
            { label: t_i18n('Events') },
            { label: t_i18n('Incidents'), link: '/dashboard/events/incidents' },
            { label: incident.name, current: true },
          ]}
          />
          <StixDomainObjectHeader
            entityType="Incident"
            stixDomainObject={incident}
            PopoverComponent={IncidentPopover}
            enableQuickSubscription={true}
          />
          <Box
            sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 4 }}
          >
            <Tabs
              value={getCurrentTab(location.pathname, incident.id, '/dashboard/events/incidents')}
            >
              <Tab
                component={Link}
                to={`/dashboard/events/incidents/${incident.id}`}
                value={`/dashboard/events/incidents/${incident.id}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/events/incidents/${incident.id}/knowledge/overview`}
                value={`/dashboard/events/incidents/${incident.id}/knowledge`}
                label={t_i18n('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/events/incidents/${incident.id}/content`}
                value={`/dashboard/events/incidents/${incident.id}/content`}
                label={t_i18n('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/events/incidents/${incident.id}/analyses`}
                value={`/dashboard/events/incidents/${incident.id}/analyses`}
                label={t_i18n('Analyses')}
              />
              <Tab
                component={Link}
                to={`/dashboard/events/incidents/${incident.id}/files`}
                value={`/dashboard/events/incidents/${incident.id}/files`}
                label={t_i18n('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/events/incidents/${incident.id}/history`}
                value={`/dashboard/events/incidents/${incident.id}/history`}
                label={t_i18n('History')}
              />
            </Tabs>
            {isOverview && (
              <StixCoreObjectSimulationResult id={incident.id} type="threat" />
            )}
          </Box>
          <Routes>
            <Route
              path="/"
              element={<Incident incidentData={incident} />}
            />
            <Route
              path="/knowledge"
              element={(
                <Navigate
                  replace={true}
                  to={`/dashboard/events/incidents/${incidentId}/knowledge/overview`}
                />
              )}
            />
            <Route
              path="/knowledge/*"
              element={<IncidentKnowledge incidentData={incident} />}
            />
            <Route
              path="/content/*"
              element={
                <StixCoreObjectContentRoot
                  stixCoreObject={incident}
                />
              }
            />
            <Route
              path="/analyses"
              element={(
                <StixCoreObjectOrStixCoreRelationshipContainers
                  stixDomainObjectOrStixCoreRelationship={incident}
                />
              )}
            />
            <Route
              path="/files"
              element={(
                <FileManager
                  id={incidentId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={incident}
                />
              )}
            />
            <Route
              path="/history"
              element={(
                <StixCoreObjectHistory
                  stixCoreObjectId={incidentId}
                />
              )}
            />
          </Routes>
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </>
  );
};

const RootIncident = () => {
  const { incidentId } = useParams() as { incidentId: string };
  const queryRef = useQueryLoading<RootIncidentQuery>(incidentQuery, {
    id: incidentId,
  });
  const link = `/dashboard/events/incidents/${incidentId}/knowledge`;
  return (
    <div>
      <Routes>
        <Route
          path="/knowledge/*"
          element={
            <StixCoreObjectKnowledgeBar
              stixCoreObjectLink={link}
              availableSections={[
                'attribution',
                'victimology',
                'attack_patterns',
                'malwares',
                'channels',
                'narratives',
                'tools',
                'vulnerabilities',
                'observables',
              ]}
            />
          }
        />
      </Routes>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootIncidentComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </div>
  );
};
export default RootIncident;
