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

import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { PirHistoryLogsFragment$data } from './__generated__/PirHistoryLogsFragment.graphql';
import { PirHistoryLogsQuery, PirHistoryLogsQuery$variables } from './__generated__/PirHistoryLogsQuery.graphql';
import { PirHistoryFragment$key } from './__generated__/PirHistoryFragment.graphql';
import { pirHistoryFilterGroup } from '../pir-history-utils';
import PirHistoryMessage from '../PirHistoryMessage';
import { useFormatter } from '../../../../components/i18n';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../../components/dataGrid/DataTable';
import { displayEntityTypeForTranslation } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';

const pirHistoryLogFragment = graphql`
  fragment PirHistoryLogFragment on Log {
    id
    event_scope
    timestamp
    user {
      name
    }
    entity_type
    context_data {
      entity_id
      entity_type
      entity_name
      message
    }
  }
`;

const pirHistoryLogsFragment = graphql`
  fragment PirHistoryLogsFragment on Query 
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "LogsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PirHistoryLogsRefetchQuery") {
    logs(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "PaginationPirHistory_logs") {
      edges {
        node {
          id
          ...PirHistoryLogFragment
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

const pirHistoryLogsQuery = graphql`
  query PirHistoryLogsQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...PirHistoryLogsFragment
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

const historyFragment = graphql`
  fragment PirHistoryFragment on Pir {
    id
    name
  }
`;

interface PirHistoryProps {
  data: PirHistoryFragment$key,
}

const PirHistory = ({ data }: PirHistoryProps) => {
  const [ref, setRef] = useState<HTMLDivElement | null>(null);
  const { t_i18n } = useFormatter();
  const { id, name } = useFragment(historyFragment, data);

  const LOCAL_STORAGE_KEY = `PirHistoryLogs-${id}`;
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
  };

  const localStorage = usePaginationLocalStorage<PirHistoryLogsQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const { viewStorage, paginationOptions, helpers } = localStorage;
  const { filters } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('History', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: {
      mode: 'and',
      filters: [],
      filterGroups: [contextFilters, pirHistoryFilterGroup(id)],
    },
  } as unknown as PirHistoryLogsQuery$variables;

  const queryRef = useQueryLoading<PirHistoryLogsQuery>(
    pirHistoryLogsQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    entity_type: {
      percentWidth: 4,
      id: 'pir_log_message',
      label: 'Type',
      render: ({ context_data }) => {
        const entityTypeLabel = t_i18n(displayEntityTypeForTranslation(context_data?.entity_type ?? ''));
        return (
          <Tooltip title={entityTypeLabel}>
            <div style={{ height: 24 }}>
              <ItemIcon type={context_data?.entity_type} />
            </div>
          </Tooltip>
        );
      },
    },
    pir_log_message: {
      percentWidth: 84,
      id: 'pir_log_message',
      label: 'Message',
      render: (log) => {
        const message = (
          <PirHistoryMessage
            log={log}
            pirName={name}
          />
        );
        return (
          <Tooltip title={message}>
            <div>{message}</div>
          </Tooltip>
        );
      },
    },
    timestamp: {
      percentWidth: 12,
    },
  };

  return queryRef && (
    <div style={{ height: 'calc(100vh - 250px)' }} ref={(r) => setRef(r)}>
      <DataTable
        rootRef={ref ?? undefined}
        removeSelectAll
        disableLineSelection
        dataColumns={dataColumns}
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        toolbarFilters={contextFilters}
        lineFragment={pirHistoryLogFragment}
        entityTypes={['History']}
        searchContextFinal={{ entityTypes: ['History'] }}
        availableFilterKeys={[
          'timestamp',
          'contextObjectLabel',
          'contextObjectMarking',
          'contextCreator',
          'contextCreatedBy',
          'contextEntityType',
          'contextEntityId',
        ]}
        resolvePath={(d: PirHistoryLogsFragment$data) => {
          return d.logs?.edges?.map((e) => e?.node);
        }}
        preloadedPaginationProps={{
          linesQuery: pirHistoryLogsQuery,
          linesFragment: pirHistoryLogsFragment,
          queryRef,
          nodePath: ['logs', 'pageInfo', 'globalCount'],
          setNumberOfElements: helpers.handleSetNumberOfElements,
        }}
      />
    </div>
  );
};

export default PirHistory;
