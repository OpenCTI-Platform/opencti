/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { Suspense } from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import { Route, Routes, useParams } from 'react-router-dom';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { PirQuery } from './__generated__/PirQuery.graphql';
import PirHeader from './PirHeader';
import PirTabs from './PirTabs';
import PirKnowledge from './pir_knowledge/PirKnowledge';
import { PirHistoryQuery } from './__generated__/PirHistoryQuery.graphql';
import { PirRedisStreamQuery } from './__generated__/PirRedisStreamQuery.graphql';
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
      ...PirOverviewCountsFragment
      ...PirOverviewCountFlaggedFragment
      ...PirOverviewDetailsFragment
      ...PirOverviewHistoryPirFragment
      ...PirOverviewTopSourcesFragment
      ...PirTabsFragment
    }
  }
`;

const redisStreamQuery = graphql`
  query PirRedisStreamQuery {
    ...PirOverviewDetailsRedisFragment
  }
`;

const pirHistoryQuery = graphql`
  query PirHistoryQuery(
    $pirId: ID!
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
  redisStreamQueryRef: PreloadedQuery<PirRedisStreamQuery>
}

const PirComponent = ({
  pirQueryRef,
  pirHistoryQueryRef,
  redisStreamQueryRef,
}: PirComponentProps) => {
  const { pir } = usePreloadedQuery(pirQuery, pirQueryRef);
  const history = usePreloadedQuery(pirHistoryQuery, pirHistoryQueryRef);
  const redisStream = usePreloadedQuery(redisStreamQuery, redisStreamQueryRef);

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
              dataRedis={redisStream}
            />
          )}
        />
        <Route
          path="/threats"
          element={<PirKnowledge data={pir} />}
        />
        <Route
          path="/activities"
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

  const redisQueryRef = useQueryLoading<PirRedisStreamQuery>(redisStreamQuery);
  const pirQueryRef = useQueryLoading<PirQuery>(pirQuery, { id: pirId });
  const pirHistoryQueryRef = useQueryLoading<PirHistoryQuery>(pirHistoryQuery, {
    first: 20,
    orderBy: 'timestamp',
    orderMode: 'desc',
    filters: pirHistoryFilterGroup,
    pirId,
  });

  return (
    <Suspense fallback={<Loader />}>
      {pirQueryRef && pirHistoryQueryRef && redisQueryRef && (
        <PirComponent
          pirQueryRef={pirQueryRef}
          pirHistoryQueryRef={pirHistoryQueryRef}
          redisStreamQueryRef={redisQueryRef}
        />
      )}
    </Suspense>
  );
};

export default Pir;
