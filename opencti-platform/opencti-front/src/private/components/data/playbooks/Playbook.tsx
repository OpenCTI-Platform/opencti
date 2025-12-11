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

import React from 'react';
import { graphql, useFragment, usePreloadedQuery } from 'react-relay';
import 'reactflow/dist/style.css';
import { ReactFlowProvider } from 'reactflow';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { ErrorBoundary } from '../../Error';
import PlaybookHeader from './PlaybookHeader';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import PlaybookFlow from './playbookFlow/PlaybookFlow';
import { Playbook_playbook$key } from './__generated__/Playbook_playbook.graphql';
import { PlaybookComponentsQuery } from './__generated__/PlaybookComponentsQuery.graphql';

const playbookFragment = graphql`
  fragment Playbook_playbook on Playbook {
    name
    ...PlaybookHeader_playbook
    ...PlaybookFlow_playbook
  }
`;

export const playbookComponentsQuery = graphql`
  query PlaybookComponentsQuery {
    ...PlaybookFlow_playbookComponents
  }
`;

interface PlaybookProps {
  dataPlaybook: Playbook_playbook$key
  playbookComponentsQueryRef: PreloadedQuery<PlaybookComponentsQuery>
}

const Playbook = ({ dataPlaybook, playbookComponentsQueryRef }: PlaybookProps) => {
  const { t_i18n } = useFormatter();
  const playbook = useFragment(playbookFragment, dataPlaybook);
  const dataPlaybookComponents = usePreloadedQuery(playbookComponentsQuery, playbookComponentsQueryRef);

  return (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Processing') },
          { label: t_i18n('Automation'), link: '/dashboard/data/processing/automation' },
          { label: playbook.name, current: true },
        ]}
      />
      <PlaybookHeader playbook={playbook} />
      <ErrorBoundary>
        <ReactFlowProvider>
          <PlaybookFlow
            dataPlaybook={playbook}
            dataPlaybookComponents={dataPlaybookComponents}
          />
        </ReactFlowProvider>
      </ErrorBoundary>
    </>
  );
};

export default Playbook;
