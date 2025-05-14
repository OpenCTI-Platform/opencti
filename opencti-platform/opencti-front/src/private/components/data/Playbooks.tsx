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

import React, { FunctionComponent } from 'react';
import ProcessingMenu from '@components/data/ProcessingMenu';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import { graphql } from 'react-relay';
import PlaybookPopover from '@components/data/playbooks/PlaybookPopover';
import { PlaybooksLines_data$data } from './__generated__/PlaybooksLines_data.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import PlaybookCreation from './playbooks/PlaybookCreation';
import { PlaybooksLinesPaginationQuery, PlaybooksLinesPaginationQuery$variables } from './__generated__/PlaybooksLinesPaginationQuery.graphql';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import ItemBoolean from '../../../components/ItemBoolean';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

export const LOCAL_STORAGE_KEY_PLAYBOOKS = 'playbooks';

const playbookFragment = graphql`
  fragment PlaybooksLine_node on Playbook {
    id
    name
    entity_type
    description
    playbook_running
    queue_messages
  }
`;

const playbooksLinesQuery = graphql`
  query PlaybooksLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: PlaybooksOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...PlaybooksLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const playbooksLinesFragment = graphql`
  fragment PlaybooksLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "PlaybooksOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PlaybooksLinesRefetchQuery") {
    playbooks(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_playbooks") {
      edges {
        node {
          entity_type
          id
          name
          description
          ...PlaybooksLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

const Playbooks: FunctionComponent = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n, n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Automation | Processing | Data'));

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<PlaybooksLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_PLAYBOOKS,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext(
    'Playbook',
    viewStorage.filters,
  );

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as PlaybooksLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<PlaybooksLinesPaginationQuery>(
    playbooksLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: playbooksLinesQuery,
    linesFragment: playbooksLinesFragment,
    queryRef,
    nodePath: ['playbooks', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<PlaybooksLinesPaginationQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      label: 'Name',
      percentWidth: 25,
    },
    description: {
      label: 'Description',
      percentWidth: 30,
      isSortable: false,
    },
    messages: {
      id: 'messages',
      label: 'Messages',
      percentWidth: 20,
      isSortable: false,
      render: ({ queue_messages }) => n(queue_messages),
    },
    playbook_running: {
      id: 'playbook_running',
      label: 'Playbook running',
      percentWidth: 25,
      isSortable: true,
      render: ({ playbook_running }) => (
        <ItemBoolean
          variant="inList"
          label={playbook_running ? t_i18n('Yes') : t_i18n('No')}
          status={playbook_running}
        />
      ),
    },
  };
  return (
    <div style={{ paddingRight: '200px', height: '100%' }}>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Processing') },
          {
            label: t_i18n('Automation'),
            current: true,
          }]}
      />
      <ProcessingMenu />
      {isEnterpriseEdition ? (
        <>
          {queryRef && (
            <DataTable
              dataColumns={dataColumns}
              resolvePath={(data: PlaybooksLines_data$data) => data.playbooks?.edges?.map((m) => m?.node)}
              storageKey={LOCAL_STORAGE_KEY_PLAYBOOKS}
              initialValues={initialValues}
              toolbarFilters={contextFilters}
              preloadedPaginationProps={preloadedPaginationProps}
              lineFragment={playbookFragment}
              entityTypes={['Playbook']}
              searchContextFinal={{ entityTypes: ['Playbook'] }}
              taskScope="PLAYBOOK"
              actions={(row) => (
                <PlaybookPopover
                  paginationOptions={queryPaginationOptions}
                  playbookId={row.id}
                  running={row.playbook_running}
                />
              )}
              createButton={
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <PlaybookCreation paginationOptions={queryPaginationOptions} />
                </Security>
              }
            />
          )}
        </>
      ) : (
        <EnterpriseEdition feature={t_i18n('Playbook')} />
      )}
    </div>
  );
};

export default Playbooks;
