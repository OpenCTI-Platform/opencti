import { startTransition, Suspense, useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { CloudRefreshOutline } from 'mdi-material-ui';
import GraphToolbarItem from '../../../../../components/graph/components/GraphToolbarItem';
import { useFormatter } from '../../../../../components/i18n';
import { GraphEntity } from '../../../../../components/graph/graph.types';
import InvestigationEnrichmentDrawer from './InvestigationEnrichmentDrawer';
import { InvestigationEnrichmentToolQuery } from './__generated__/InvestigationEnrichmentToolQuery.graphql';
import useIntervalBoostable from '../../../../../utils/hooks/useIntervalBoostable';
import InvestigationEnrichmentButton from './InvestigationEnrichmentButton';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';
import { addInEnrichmentMap } from './investigation-enrichment.utils';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';

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
            investigation_status
            eventSource {
              ...on StixCoreObject {
                id
                entity_type
                representative {
                  main
                }
              }
              ...on StixCoreRelationship {
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
            touchedElements {
              ...on StixCoreObject {
                id
                entity_type
              }
              ...on StixCoreRelationship {
                id
                entity_type
                fromId
                toId
              }
              ...on StixSightingRelationship {
                id
                entity_type
                fromId
                toId
              }
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
  onExpand?: (newObjects: ObjectToParse[]) => void;
}

const InvestigationEnrichmentToolComponent = ({
  queryRef,
  onRefresh,
  onExpand,
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
        if (work.node.investigation_status === 'TO_REVIEW') {
          addInEnrichmentMap(toreview, work.node);
        } else if (work.node.status === 'complete' || work.node.status === 'timeout') {
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
        askRefresh={onRefresh}
        onExpand={onExpand}
      />
    </>
  );
};

interface InvestigationEnrichmentToolProps {
  entity: GraphEntity;
  onExpand?: (newObjects: ObjectToParse[]) => void;
}

const InvestigationEnrichmentTool = ({
  entity,
  onExpand,
}: InvestigationEnrichmentToolProps) => {
  const { t_i18n } = useFormatter();
  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;
  const selectionIds = [...selectedNodes, ...selectedLinks].map((selected) => selected.id);
  const selectionKey = [...selectionIds].sort().join(',');

  // Loaded by refetch only: a second load in the same tick as the first one, one urgent and one in a transition,
  // makes Relay release a reference React still renders ("Expected preloadedQuery to not be disposed yet").
  const [queryRef, loadQuery] = useQueryLoader<InvestigationEnrichmentToolQuery>(investigationQuery);

  /**
   * Loads the works of the selection. The first load is urgent, so that the fallback shows meanwhile;
   * the next ones are transitions, so that the loaded works stay on screen until the new ones arrive.
   */
  const refetch = () => {
    const variables = {
      id: entity.id,
      entityIds: selectionIds.length > 0 ? selectionIds : undefined,
    };
    const load = () => loadQuery(variables, { fetchPolicy: 'network-only' });
    if (!queryRef) {
      load();
    } else {
      startTransition(load);
    }
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
          onExpand={onExpand}
        />
      )}
    </Suspense>
  );
};

export default InvestigationEnrichmentTool;
