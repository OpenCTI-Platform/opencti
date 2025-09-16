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
import PirOverview from './pir_overview/PirOverview';
import ErrorNotFound from '../../../components/ErrorNotFound';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader from '../../../components/Loader';
import PirAnalyses from './pir_analyses/PirAnalyses';
import PirHistory from './pir_history/PirHistory';

const pirQuery = graphql`
  query PirQuery($id: ID!) {
    pir(id: $id) {
      ...PirAnalysesFragment
      ...PirEditionFragment
      ...PirHeaderFragment
      ...PirHistoryFragment
      ...PirKnowledgeFragment
      ...PirOverviewFragment
      ...PirTabsFragment
    }
  }
`;

interface PirComponentProps {
  pirQueryRef: PreloadedQuery<PirQuery>
}

const PirComponent = ({
  pirQueryRef,
}: PirComponentProps) => {
  const { pir } = usePreloadedQuery(pirQuery, pirQueryRef);

  if (!pir) return <ErrorNotFound/>;

  return (
    <>
      <PirHeader data={pir} editionData={pir} />
      <PirTabs data={pir} />
      <Routes>
        <Route
          path="/"
          element={<PirOverview data={pir} />}
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
  const pirQueryRef = useQueryLoading<PirQuery>(pirQuery, { id: pirId });

  return (
    <Suspense fallback={<Loader />}>
      {pirQueryRef && <PirComponent pirQueryRef={pirQueryRef} />}
    </Suspense>
  );
};

export default Pir;
