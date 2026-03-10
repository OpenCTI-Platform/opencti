// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootReportSubscription } from '@components/analyses/reports/__generated__/RootReportSubscription.graphql';
import Security from 'src/utils/Security';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import GroupingDeletion from '@components/analyses/groupings/GroupingDeletion';
import StixCoreObjectSecurityCoverage from '@components/common/stix_core_objects/StixCoreObjectSecurityCoverage';
import AIInsights from '@components/common/ai/AIInsights';
import { QueryRenderer } from '../../../../relay/environment';
import Grouping from './Grouping';
import GroupingKnowledge from './GroupingKnowledge';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import { useFormatter } from '../../../../components/i18n';
import { useEntityLabelResolver } from '../../../../utils/hooks/useEntityLabel';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { getPaddingRight } from '../../../../utils/utils';
import GroupingEdition from './GroupingEdition';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';

const subscription = graphql`
  subscription RootGroupingSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Grouping {
        ...Grouping_grouping
        ...GroupingEditionContainer_grouping
        ...StixCoreObjectContent_stixCoreObject
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const groupingQuery = graphql`
  query RootGroupingQuery($id: String!) {
    grouping(id: $id) {
      id
      standard_id
      entity_type
      name
      currentUserAccessRight
      securityCoverage {
        id
        coverage_information {
          coverage_name
          coverage_score
        }
      }
      ...Grouping_grouping
      ...GroupingDetails_grouping
      ...GroupingKnowledge_grouping
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixCyberObservables_container
      ...StixCoreObjectContent_stixCoreObject
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
    connectorsForExport {
      ...StixCoreObjectFilesAndHistory_connectorsExport
    }
    connectorsForImport {
      ...StixCoreObjectFilesAndHistory_connectorsImport
    }
  }
`;

const RootGrouping = () => {
  const { groupingId } = useParams() as { groupingId: string };
  const subConfig = useMemo<
    GraphQLSubscriptionConfig<RootReportSubscription>
  >(
    () => ({
      subscription,
      variables: { id: groupingId },
    }),
    [groupingId],
  );
  const location = useLocation();
  const enableReferences = useIsEnforceReference('Grouping') && !useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]);
  const { t_i18n } = useFormatter();
  const entityLabel = useEntityLabelResolver();
  useSubscription(subConfig);

  return (
    <>
      <QueryRenderer
        query={groupingQuery}
        variables={{ id: groupingId }}
        render={({ props }) => {
          if (props) {
            if (props.grouping) {
              const { grouping } = props;
              const isKnowledgeOrContent = location.pathname.includes('knowledge') || location.pathname.includes('content');
              const paddingRight = getPaddingRight(location.pathname, grouping.id, '/dashboard/analyses/groupings', false);
              const currentAccessRight = useGetCurrentUserAccessRight(grouping.currentUserAccessRight);
              return (
                <div style={{ paddingRight }}>
                  <Breadcrumbs elements={[
                    { label: t_i18n('Analyses') },
                    { label: entityLabel('Grouping', t_i18n('Groupings')), link: '/dashboard/analyses/groupings' },
                    { label: grouping.name, current: true },
                  ]}
                  />
                  <ContainerHeader
                    container={grouping}
                    EditComponent={(
                      <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={currentAccessRight.canEdit}>
                        <GroupingEdition groupingId={grouping.id} />
                      </Security>
                    )}
                    DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                      <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]} hasAccess={currentAccessRight.canEdit}>
                        <GroupingDeletion groupingId={grouping.id} isOpen={isOpen} handleClose={onClose} />
                      </Security>
                    )}
                    enableQuickSubscription={true}
                    enableQuickExport={true}
                    redirectToContent={true}
                    enableEnricher={true}
                    enableEnrollPlaybook={true}
                  />
                  <StixDomainObjectTabsBox
                    basePath="/dashboard/analyses/groupings"
                    entity={grouping}
                    tabs={[
                      'overview',
                      'knowledge',
                      'content',
                      'entities',
                      'observables',
                      'files',
                    ]}
                    extraActions={!isKnowledgeOrContent && (
                      <>
                        <AIInsights id={grouping.id} tabs={['containers']} defaultTab="containers" isContainer={true} />
                        <StixCoreObjectSecurityCoverage id={grouping.id} coverage={grouping.securityCoverage} />
                      </>
                    )}
                  />
                  <Routes>
                    <Route
                      path="/"
                      element={
                        <Grouping grouping={grouping} />
                      }
                    />
                    <Route
                      path="/entities"
                      element={(
                        <ContainerStixDomainObjects
                          container={grouping}
                          enableReferences={enableReferences}
                        />
                      )}
                    />
                    <Route
                      path="/observables"
                      element={(
                        <ContainerStixCyberObservables
                          container={grouping}
                          enableReferences={enableReferences}
                        />
                      )}
                    />
                    <Route
                      path="/content/*"
                      element={(
                        <StixCoreObjectContentRoot
                          stixCoreObject={grouping}
                          isContainer={true}
                        />
                      )}
                    />
                    <Route
                      path="/knowledge"
                      element={(
                        <Navigate
                          replace={true}
                          to={`/dashboard/analyses/groupings/${groupingId}/knowledge/graph`}
                        />
                      )}
                    />
                    <Route
                      path="/knowledge/*"
                      element={(
                        <GroupingKnowledge
                          grouping={grouping}
                          enableReferences={enableReferences}
                        />
                      )}
                    />
                    <Route
                      path="/files"
                      element={(
                        <StixCoreObjectFilesAndHistory
                          id={groupingId}
                          connectorsExport={props.connectorsForExport}
                          connectorsImport={props.connectorsForImport}
                          entity={props.grouping}
                          withoutRelations={true}
                          bypassEntityId={true}
                        />
                      )}
                    />
                  </Routes>
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
};

export default RootGrouping;
