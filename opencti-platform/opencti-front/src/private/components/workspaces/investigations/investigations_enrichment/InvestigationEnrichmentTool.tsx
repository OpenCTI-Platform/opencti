import { startTransition, Suspense, useState } from 'react';
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

const investigationQuery = graphql`
  query InvestigationEnrichmentToolQuery($id: String!) {
    workspace(id: $id) {
      id
      currentUserAccessRight
      enrichmentWorks {
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

  if (!investigation) {
    return null;
  }

  return (
    <>
      <InvestigationEnrichmentButton
        investigation={investigation}
        onClick={() => setOpenEnrichment(true)}
      />

      <InvestigationEnrichmentDrawer
        open={openEnrichment}
        investigation={investigation}
        onClose={() => setOpenEnrichment(false)}
        onLaunchCompleted={onRefresh}
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

  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<InvestigationEnrichmentToolQuery>(
    investigationQuery,
    { id: entity.id },
  );

  const { activateBoost } = useIntervalBoostable(() => {
    startTransition(() => {
      loadQuery({ id: entity.id }, { fetchPolicy: 'network-only' });
    });
  }, {
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
