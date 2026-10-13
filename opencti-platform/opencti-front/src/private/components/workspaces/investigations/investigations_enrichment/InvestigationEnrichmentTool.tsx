import { startTransition, Suspense, useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { CloudRefreshOutline } from 'mdi-material-ui';
import GraphToolbarItem from '../../../../../components/graph/components/GraphToolbarItem';
import { useFormatter } from '../../../../../components/i18n';
import { GraphEntity } from '../../../../../components/graph/graph.types';
import InvestigationEnrichmentDrawer from './InvestigationEnrichmentDrawer';
import { useQueryLoadingWithLoadQuery } from '../../../../../utils/hooks/useQueryLoading';
import { InvestigationEnrichmentToolQuery } from './__generated__/InvestigationEnrichmentToolQuery.graphql';
import useIntervalBoostable from '../../../../../utils/hooks/useIntervalBoostable';
import InvestigationEnrichmentButton from './InvestigationEnrichmentButton';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';
import { addInEnrichmentMap } from './investigation-enrichment.utils';

const investigationQuery = graphql`
  query InvestigationEnrichmentToolQuery($id: String!, $entityIds: [String!]) {
    workspace(id: $id) {
      id
      currentUserAccessRight
      enrichmentWorks(entityIds: $entityIds) {
        edges {
          node {
            id
            status
            event_source_id
            eventSource {
              ...on StixObject {
                id
                entity_type
                representative {
                  main
                }
              }
              ...on StixRelationship {
                id
                entity_type
                representative {
                  main
                }
              }
            }
            timestamp
            messages {
              timestamp
              message
            }
            errors {
              timestamp
              message
            }
            connector {
              id
              name
              active
              connector_type
            }
          }
        }
      }
    }
  }
`;

interface InvestigationEnrichmentToolComponentProps {
  queryRef: PreloadedQuery<InvestigationEnrichmentToolQuery>;
  onRefresh: () => void;
}

const InvestigationEnrichmentToolComponent = ({
  queryRef,
  onRefresh,
}: InvestigationEnrichmentToolComponentProps) => {
  const [openEnrichment, setOpenEnrichment] = useState(false);
  const { workspace: investigation } = usePreloadedQuery(investigationQuery, queryRef);

  const { works, haveErrors, nbWorks } = useMemo(() => {
    let worksInError = false;
    const done = new Map<string, InvestigationEnrichmentWork[]>();
    const ongoing = new Map<string, InvestigationEnrichmentWork[]>();
    const toreview = new Map<string, InvestigationEnrichmentWork[]>(); // TODO
    investigation?.enrichmentWorks?.edges?.forEach((work) => {
      if (work?.node) {
        if ((work.node.errors ?? []).length > 0) worksInError = true;
        if (work.node.status === 'complete' || work.node.status === 'timeout') {
          addInEnrichmentMap(done, work.node);
        } else {
          addInEnrichmentMap(ongoing, work.node);
        }
      }
    });
    return {
      works: { ongoing, done, toreview },
      haveErrors: worksInError,
      nbWorks: investigation?.enrichmentWorks?.edges?.length ?? 0,
    };
  }, [investigation]);

  if (!investigation) {
    return null;
  }

  return (
    <>
      <InvestigationEnrichmentButton
        works={works}
        nbWorks={nbWorks}
        haveWorksInErrors={haveErrors}
        investigation={investigation}
        onClick={() => setOpenEnrichment(true)}
      />

      <InvestigationEnrichmentDrawer
        open={openEnrichment}
        investigation={investigation}
        works={works}
        onClose={() => setOpenEnrichment(false)}
        onLaunchCompleted={onRefresh}
        onWorkDeleted={onRefresh}
        onEnrichment={onRefresh}
      />
    </>
  );
};

interface InvestigationEnrichmentToolProps {
  entity: GraphEntity;
}

const InvestigationEnrichmentTool = ({
  entity,
}: InvestigationEnrichmentToolProps) => {
  const { t_i18n } = useFormatter();
  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;
  const selectionIds = [...selectedNodes, ...selectedLinks].map((selected) => selected.id);
  const selectionKey = [...selectionIds].sort().join(',');

  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<InvestigationEnrichmentToolQuery>(
    investigationQuery,
    { id: entity.id },
  );

  const refetch = () => {
    const variables = {
      id: entity.id,
      entityIds: selectionIds.length > 0 ? selectionIds : undefined,
    };
    startTransition(() => {
      loadQuery(variables, { fetchPolicy: 'network-only' });
    });
  };

  useEffect(() => {
    refetch();
  }, [selectionKey]);

  const { activateBoost } = useIntervalBoostable(refetch, {
    baseFrequency: 10000,
    boostFrequency: 2000,
    boostDuration: 10000,
  });

  const fallback = (
    <GraphToolbarItem
      disabled
      color="primary"
      title={t_i18n('Enrichment')}
      Icon={<CloudRefreshOutline />}
    />
  );

  return (
    <Suspense fallback={fallback}>
      {queryRef && (
        <InvestigationEnrichmentToolComponent
          queryRef={queryRef}
          onRefresh={activateBoost}
        />
      )}
    </Suspense>
  );
};

export default InvestigationEnrichmentTool;
