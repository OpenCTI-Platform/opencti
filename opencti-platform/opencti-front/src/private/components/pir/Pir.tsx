import React, { Suspense } from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import { Route, Routes, useParams } from 'react-router-dom';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { PirQuery } from './__generated__/PirQuery.graphql';
import PirHeader from './PirHeader';
import PirTabs from './PirTabs';
import PirKnowledge from './PirKnowledge';
import { PirHistoryQuery } from './__generated__/PirHistoryQuery.graphql';
import PirOverview from './PirOverview';
import ErrorNotFound from '../../../components/ErrorNotFound';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader from '../../../components/Loader';
import { PirThreatMapQuery } from './__generated__/PirThreatMapQuery.graphql';

const pirQuery = graphql`
  query PirQuery($id: ID!) {
    pir(id: $id) {
      id
      ...PirHeaderFragment
      ...PirKnowledgeFragment
      ...PirEditionFragment
      ...PirOverviewDetailsFragment
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

const pirThreatMapQuery = graphql`
  query PirThreatMapQuery($toId: StixRef!) {
    ...PirOverviewThreatMapFragment
  }
`;

interface PirComponentProps {
  pirQueryRef: PreloadedQuery<PirQuery>
  pirHistoryQueryRef: PreloadedQuery<PirHistoryQuery>
  pirThreatMapQueryRef: PreloadedQuery<PirThreatMapQuery>
}

const PirComponent = ({
  pirQueryRef,
  pirHistoryQueryRef,
  pirThreatMapQueryRef,
}: PirComponentProps) => {
  const { pir } = usePreloadedQuery(pirQuery, pirQueryRef);
  const history = usePreloadedQuery(pirHistoryQuery, pirHistoryQueryRef);
  const relationships = usePreloadedQuery(pirThreatMapQuery, pirThreatMapQueryRef);

  if (!pir) return <ErrorNotFound/>;

  return (
    <>
      <PirHeader data={pir} editionData={pir} />
      <PirTabs pirId={pir.id} />
      <Routes>
        <Route
          path="/"
          element={(
            <PirOverview
              dataHistory={history}
              dataDetails={pir}
              dataThreatMap={relationships}
            />
          )}
        />
        <Route
          path="/knowledge"
          element={<PirKnowledge data={pir} />}
        />
        <Route
          path="/ttps"
          element={<p>ttps</p>}
        />
        <Route
          path="/analyses"
          element={<p>analyses</p>}
        />
      </Routes>
    </>
  );
};

const Pir = () => {
  const { pirId } = useParams() as { pirId?: string };
  if (!pirId) return <ErrorNotFound/>;

  const pirQueryRef = useQueryLoading<PirQuery>(pirQuery, { id: pirId });
  const pirThreatMapQueryRef = useQueryLoading<PirThreatMapQuery>(pirThreatMapQuery, { toId: pirId });
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
            values: ['create', 'delete', 'update'],
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
      {pirQueryRef && pirHistoryQueryRef && pirThreatMapQueryRef && (
        <PirComponent
          pirQueryRef={pirQueryRef}
          pirHistoryQueryRef={pirHistoryQueryRef}
          pirThreatMapQueryRef={pirThreatMapQueryRef}
        />
      )}
    </Suspense>
  );
};

export default Pir;
