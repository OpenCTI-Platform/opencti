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

import React, { Suspense, useEffect } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { RootPlaybookQuery } from './__generated__/RootPlaybookQuery.graphql';
import { PlaybookComponentsQuery } from './__generated__/PlaybookComponentsQuery.graphql';
import Playbook, { playbookComponentsQuery } from './Playbook';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const playbookQuery = graphql`
  query RootPlaybookQuery($id: String!) {
    playbook(id: $id) {
      ...Playbook_playbook
    }
  }
`;

interface RootPlaybookComponentProps {
  playbookQueryRef: PreloadedQuery<RootPlaybookQuery>;
  playbookComponentsQueryRef: PreloadedQuery<PlaybookComponentsQuery>;
}

const RootPlaybookComponent = ({
  playbookQueryRef,
  playbookComponentsQueryRef,
}: RootPlaybookComponentProps) => {
  const data = usePreloadedQuery(playbookQuery, playbookQueryRef);
  const { playbook } = data;
  if (!playbook) return <ErrorNotFound />;

  return (
    <Routes>
      <Route
        path="/"
        element={(
          <Playbook
            dataPlaybook={playbook}
            playbookComponentsQueryRef={playbookComponentsQueryRef}
          />
        )}
      />
    </Routes>
  );
};

const RootPlaybook = () => {
  const { playbookId } = useParams();
  if (!playbookId) return <ErrorNotFound />;

  const playbookComponentsQueryRef = useQueryLoading<PlaybookComponentsQuery>(
    playbookComponentsQuery,
  );

  const [playbookQueryRef, loadPlaybookQuery] = useQueryLoader<RootPlaybookQuery>(playbookQuery);
  useEffect(() => {
    loadPlaybookQuery({ id: playbookId }, { fetchPolicy: 'network-only' });
  }, [playbookId]);

  return (
    <Suspense fallback={<Loader />}>
      {playbookQueryRef && playbookComponentsQueryRef && (
        <RootPlaybookComponent
          playbookQueryRef={playbookQueryRef}
          playbookComponentsQueryRef={playbookComponentsQueryRef}
        />
      )}
    </Suspense>
  );
};

export default RootPlaybook;
