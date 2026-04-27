// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootReportSubscription } from '@components/analyses/reports/__generated__/RootReportSubscription.graphql';
import Security from 'src/utils/Security';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
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
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { getPaddingRight } from '../../../../utils/utils';
import GroupingEdition from './GroupingEdition';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import { PATH_GROUPING, PATH_GROUPINGS } from '@components/common/routes/paths';

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
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
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
  useSubscription(subConfig);

  const basePath = PATH_GROUPING(groupingId);
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
              const paddingRight = getPaddingRight(location.pathname, basePath, false);
              const currentAccessRight = useGetCurrentUserAccessRight(grouping.currentUserAccessRight);
              return (
                <div style={{ paddingRight }}>
                  <Breadcrumbs elements={[
                    { label: t_i18n('Analyses') },
                    { label: t_i18n('Groupings'), link: PATH_GROUPINGS },
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
                  <StixDomainObjectMain
                    basePath={basePath}
                    pages={{
                      overview:
                        <Grouping grouping={grouping} />,
                      knowledge: (
                        <GroupingKnowledge
                          grouping={grouping}
                          enableReferences={enableReferences}
                        />
                      ),
                      content: (
                        <StixCoreObjectContentRoot
                          stixCoreObject={grouping}
                          isContainer={true}
                        />
                      ),
                      entities: (
                        <ContainerStixDomainObjects
                          container={grouping}
                          enableReferences={enableReferences}
                        />
                      ),
                      observables: (
                        <ContainerStixCyberObservables
                          container={grouping}
                          enableReferences={enableReferences}
                        />
                      ),
                      files: (
                        <StixCoreObjectFilesAndHistory
                          id={groupingId}
                          connectorsExport={props.connectorsForExport}
                          connectorsImport={props.connectorsForImport}
                          entity={props.grouping}
                          withoutRelations={true}
                          bypassEntityId={true}
                        />
                      ),
                    }}
                    extraActions={!isKnowledgeOrContent && (
                      <>
                        <AIInsights id={grouping.id} tabs={['containers']} defaultTab="containers" isContainer={true} />
                        <StixCoreObjectSecurityCoverage id={grouping.id} coverage={grouping.securityCoverage} />
                      </>
                    )}
                  />
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
