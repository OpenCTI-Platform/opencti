import React, { Suspense } from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import { Route, Routes, useParams } from 'react-router-dom';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { PirQuery } from './__generated__/PirQuery.graphql';
import PirHeader from './PirHeader';
import PirTabs from './PirTabs';
import PirKnowledge from './pir_knowledge/PirKnowledge';
import { PirHistoryQuery } from './__generated__/PirHistoryQuery.graphql';
import PirOverview from './pir_overview/PirOverview';
import ErrorNotFound from '../../../components/ErrorNotFound';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader from '../../../components/Loader';
import PirAnalyses from './pir_analyses/PirAnalyses';
import PirHistory from './pir_history/PirHistory';
import { pirHistoryFilterGroup } from './pir-history-utils';

const pirQuery = graphql`
  query PirQuery($id: ID!) {
    pir(id: $id) {
      ...PirAnalysesFragment
      ...PirEditionFragment
      ...PirHeaderFragment
      ...PirHistoryFragment
      ...PirKnowledgeFragment
      ...PirOverviewFragment
      ...PirOverviewCountsFragment
      ...PirOverviewCountFlaggedFragment
      ...PirOverviewDetailsFragment
      ...PirOverviewHistoryPirFragment
      ...PirOverviewTopSourcesFragment
      ...PirTabsFragment
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

const PirComponent = ({
  pirQueryRef,
  pirHistoryQueryRef,
}: PirComponentProps) => {
  const { pir } = usePreloadedQuery(pirQuery, pirQueryRef);
  const history = usePreloadedQuery(pirHistoryQuery, pirHistoryQueryRef);

  if (!pir) return <ErrorNotFound/>;

  return (
    <>
      <PirHeader data={pir} editionData={pir} />
      <PirTabs data={pir} />
      <Routes>
        <Route
          path="/"
          element={(
            <PirOverview
              dataHistory={history}
              dataPir={pir}
            />
          )}
        />
        <Route
          path="/threats"
          element={<PirKnowledge data={pir} />}
        />
        <Route
          path="/history"
          element={<PirHistory data={pir} />}
        />
        <Route
          path="/analyses"
          element={<PirAnalyses data={pir} />}
        />
      </Routes>
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
    filters: pirHistoryFilterGroup(pirId),
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
