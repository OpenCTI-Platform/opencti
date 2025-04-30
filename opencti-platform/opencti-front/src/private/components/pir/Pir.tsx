import React, { Suspense } from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import { PirQuery } from '@components/pir/__generated__/PirQuery.graphql';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import PirHeader from '@components/pir/PirHeader';
import PirTabs from '@components/pir/PirTabs';
import PirKnowledge from '@components/pir/PirKnowledge';
import { PirHistoryQuery } from '@components/pir/__generated__/PirHistoryQuery.graphql';
import PirOverview from '@components/pir/PirOverview';
import ErrorNotFound from '../../../components/ErrorNotFound';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader from '../../../components/Loader';

const pirQuery = graphql`
  query PirQuery($id: ID!) {
    pir(id: $id) {
      ...PirHeaderFragment
      ...PirKnowledgeFragment
    }
  }
`;

const pirHistoryQuery = graphql`
  query PirHistoryQuery(
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    ...PirOverviewHistoryFragment
  }
`;

interface PirComponentProps {
  pirQueryRef: PreloadedQuery<PirQuery>
  pirHistoryQueryRef: PreloadedQuery<PirHistoryQuery>
}

const PirComponent = ({ pirQueryRef, pirHistoryQueryRef }: PirComponentProps) => {
  const { pir } = usePreloadedQuery(pirQuery, pirQueryRef);
  const history = usePreloadedQuery(pirHistoryQuery, pirHistoryQueryRef);

  if (!pir) return <ErrorNotFound/>;

  return (
    <>
      <PirHeader data={pir} />
      <PirTabs>
        {({ index }) => (
          <>
            <div role="tabpanel" hidden={index !== 0}>
              <PirOverview data={history} />
            </div>
            <div role="tabpanel" hidden={index !== 1}>
              <PirKnowledge data={pir} />
            </div>
            <div role="tabpanel" hidden={index !== 2}>
              ttps
            </div>
            <div role="tabpanel" hidden={index !== 3}>
              analyses
            </div>
          </>
        )}
      </PirTabs>
    </>
  );
};

const Pir = () => {
  const { pirId } = useParams() as { pirId?: string };
  if (!pirId) return <ErrorNotFound/>;

  const pirQueryRef = useQueryLoading<PirQuery>(pirQuery, { id: pirId });
  const pirHistoryQueryRef = useQueryLoading<PirHistoryQuery>(pirHistoryQuery, {
    first: 20,
    orderBy: 'timestamp',
    orderMode: 'desc',
    filters: {
      mode: 'and',
      filters: [
        {
          key: ['event_type'],
          values: ['create', 'delete', 'mutation'], // retro-compatibility
        },
      ],
      filterGroups: [{
        mode: 'or',
        filters: [
          {
            key: ['event_scope'],
            values: ['create', 'delete'],
          },
          {
            key: ['event_scope'],
            values: [], // if event_scope is null, event_type is not
            operator: 'nil',
          },
        ],
        filterGroups: [],
      },
      {
        mode: 'or',
        filters: [
          {
            key: ['context_data.pir_ids'],
            values: [pirId],
          },
        ],
        filterGroups: [],
      }],
    },
  });

  return (
    <Suspense fallback={<Loader />}>
      {pirQueryRef && pirHistoryQueryRef && (
        <PirComponent
          pirQueryRef={pirQueryRef}
          pirHistoryQueryRef={pirHistoryQueryRef}
        />
      )}
    </Suspense>
  );
};

export default Pir;
