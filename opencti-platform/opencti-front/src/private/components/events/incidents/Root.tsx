// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Routes, useParams, useLocation } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import StixCoreObjectSecurityCoverage from '@components/common/stix_core_objects/StixCoreObjectSecurityCoverage';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from 'src/utils/hooks/useGranted';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import AIInsights from '@components/common/ai/AIInsights';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import Incident from './Incident';
import IncidentKnowledge from './IncidentKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import FileManager from '../../common/files/FileManager';
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
import IncidentEdition from './IncidentEdition';
import IncidentDeletion from './IncidentDeletion';

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
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      currentUserAccessRight
      securityCoverage {
        id
        coverage_information {
          coverage_name
          coverage_score
        }
      }
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...Incident_incident
      ...IncidentKnowledge_incident
      ...StixCoreObjectContent_stixCoreObject
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectSharingListFragment
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
  const { forceUpdate } = useForceUpdate();
  const { incident, connectorsForImport, connectorsForExport } = data;
  const link = `/dashboard/events/incidents/${incidentId}/knowledge`;
  const isOverview = location.pathname === `/dashboard/events/incidents/${incident?.id}`;
  const paddingRightValue = () => {
    if (location.pathname.includes(`/dashboard/events/incidents/${incident.id}/knowledge`)) return 200;
    if (location.pathname.includes(`/dashboard/events/incidents/${incident.id}/content`)) return 350;
    if (location.pathname.includes(`/dashboard/events/incidents/${incident.id}/content/mapping`)) return 0;
    return 0;
  };
  return (
    <CreateRelationshipContextProvider>
      {incident ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
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
                    'indicators',
                    'observables',
                  ]}
                  data={incident}
                  attribution={['Threat-Actor-Individual', 'Threat-Actor-Group', 'Intrusion-Set', 'Campaign']}
                />
              )}
            />
          </Routes>
          <div
            style={{ paddingRight: paddingRightValue() }}
          >
            <Breadcrumbs elements={[
              { label: t_i18n('Events') },
              { label: t_i18n('Incidents'), link: '/dashboard/events/incidents' },
              { label: incident.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Incident"
              stixDomainObject={incident}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <IncidentEdition incidentId={incident.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={incident}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <IncidentDeletion id={incident.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              enableQuickSubscription={true}
              redirectToContent={true}
              enableEnricher={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectMain
              basePath="/dashboard/events/incidents"
              entity={incident}
              pages={{
                overview: <Incident incidentData={incident} />,
                knowledge: (
                  <div key={forceUpdate}>
                    <IncidentKnowledge incidentData={incident} />
                  </div>
                ),
                content: (
                  <StixCoreObjectContentRoot
                    stixCoreObject={incident}
                  />
                ),
                analyses: (
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    stixDomainObjectOrStixCoreRelationship={incident}
                  />
                ),
                files: (
                  <FileManager
                    id={incidentId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={incident}
                  />
                ),
                history: (
                  <StixCoreObjectHistory
                    stixCoreObjectId={incidentId}
                  />
                ),
              }}
              extraActions={isOverview && (
                <>
                  <AIInsights id={incident.id} />
                  <StixCoreObjectSecurityCoverage id={incident.id} coverage={incident.securityCoverage} />
                </>
              )}
            />
          </div>
        </>
      ) : (
        <ErrorNotFound />
      )}
    </CreateRelationshipContextProvider>
  );
};

const RootIncident = () => {
  const { incidentId } = useParams() as { incidentId: string };
  const queryRef = useQueryLoading<RootIncidentQuery>(incidentQuery, {
    id: incidentId,
  });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootIncidentComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};
export default RootIncident;
