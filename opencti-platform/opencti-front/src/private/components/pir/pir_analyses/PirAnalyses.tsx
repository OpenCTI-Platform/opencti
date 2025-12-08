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

import { graphql, useFragment } from 'react-relay';
import React, { useState } from 'react';
import { Chip, Tooltip, Alert } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { PirAnalysesContainersListQuery, PirAnalysesContainersListQuery$variables } from './__generated__/PirAnalysesContainersListQuery.graphql';
import { PirAnalyses_ContainersFragment$data } from './__generated__/PirAnalyses_ContainersFragment.graphql';
import { emptyFilterGroup, getFilterKeyValues, sanitizeFilterGroupKeysForBackend, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useAuth from '../../../../utils/hooks/useAuth';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../../components/dataGrid/DataTable';
import { PirAnalysesFragment$key } from './__generated__/PirAnalysesFragment.graphql';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { itemColor } from '../../../../utils/Colors';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

const pirAnalysesContainerFragment = graphql`
  fragment PirAnalyses_ContainerFragment on Container
  @argumentDefinitions(
    objectsFilters: { type: "FilterGroup" }
  ) {
    id
    entity_type
    created
    status {
      id
      order
      template {
        id
        name
        color
      }
    }
    representative {
      main
    }
    objectMarking {
      id
      definition
      definition_type
    }
    createdBy {
      id
      name
    }
    creators {
      id
      name
    }
    objects(first: 100, filters: $objectsFilters) {
      edges {
        node {
          ...on StixCoreObject {
            entity_type
            representative {
              main
            }
          }
        }
      }
    }
  }
`;

const pirAnalysesContainersFragment = graphql`
  fragment PirAnalyses_ContainersFragment on Query
  @argumentDefinitions(
    id: { type: "ID!" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ContainersOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
    objectsFilters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PirAnalyses_ContainersListRefetchQuery") {
    pir(id: $id) {
      pirContainers(
        search: $search
        first: $count
        after: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      ) @connection(key: "PaginationPirAnalyses_pirContainers") {
        edges {
          node {
            id
            ...PirAnalyses_ContainerFragment
            @arguments(objectsFilters: $objectsFilters)
          }
        }
        pageInfo {
          endCursor
          hasNextPage
          globalCount
        }
      }
    }
  }
`;

const pirAnalysesContainersListQuery = graphql`
  query PirAnalysesContainersListQuery(
    $id: ID!
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ContainersOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $objectsFilters: FilterGroup
  ) {
    ...PirAnalyses_ContainersFragment
    @arguments(
      id: $id
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      objectsFilters: $objectsFilters
    )
  }
`;

const analysesFragment = graphql`
  fragment PirAnalysesFragment on Pir {
    id
    pir_criteria {
      filters
    }
  }
`;

type PirContainerObjects = NonNullable<NonNullable<PirAnalyses_ContainersFragment$data['pir']>['pirContainers']>;

interface PirAnalysesProps {
  data: PirAnalysesFragment$key,
}

const PirAnalyses = ({ data }: PirAnalysesProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { id, pir_criteria } = useFragment(analysesFragment, data);

  const [ref, setRef] = useState<HTMLDivElement | null>(null);

  const LOCAL_STORAGE_KEY = `PirAnalysesContainersList-${id}`;
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
  };

  const localStorage = usePaginationLocalStorage<PirAnalysesContainersListQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const { viewStorage, paginationOptions, helpers } = localStorage;

  const filters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(viewStorage.filters, ['Container']);

  const pirFilters: FilterGroup[] = pir_criteria.map((c) => JSON.parse(c.filters));
  const pirToIdFilterIds = pirFilters.flatMap((f) => getFilterKeyValues('toId', f));

  const queryPaginationOptions: PirAnalysesContainersListQuery$variables = {
    ...paginationOptions,
    id,
    count: 100,
    filters: filters ? sanitizeFilterGroupKeysForBackend(filters) : undefined,
    objectsFilters: {
      mode: 'or',
      filterGroups: [],
      filters: [
        { key: ['ids'], values: pirToIdFilterIds },
        {
          key: ['regardingOf'],
          values: [
            { key: 'relationship_type', values: ['in-pir'] },
            { key: 'id', values: [id] },
          ],
        },
      ],
    },
  };

  const queryRef = useQueryLoading<PirAnalysesContainersListQuery>(
    pirAnalysesContainersListQuery,
    queryPaginationOptions,
  );

  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const dataColumns: DataTableProps['dataColumns'] = {
    entity_type: { percentWidth: 10 },
    name: {
      percentWidth: 29,
    },
    container_objects: {
      id: 'container_objects',
      label: 'Entities in PIR',
      percentWidth: 10,
      isSortable: false,
      render: ({ objects }: { objects: PirContainerObjects }) => {
        const max = 10;
        const hasMore = objects.edges.length > max;
        const countLabel = !hasMore ? objects.edges.length : `${max}+`;
        return (
          <Tooltip
            title={(
              <div style={{
                display: 'flex',
                flexDirection: 'column',
                gap: theme.spacing(1),
                padding: theme.spacing(1),
              }}
              >
                {// eslint-disable-next-line @typescript-eslint/no-explicit-any
                  objects.edges.slice(0, max).map((e: any, i: number) => (
                    <div
                      key={i}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: theme.spacing(1),
                      }}
                    >
                      <div
                        style={{
                          width: 10,
                          height: 10,
                          borderRadius: 10,
                          background: itemColor(e.node.entity_type),
                        }}
                      />
                      <div style={{ flex: 1 }}>
                        {e.node.representative.main} ({t_i18n(e.node.entity_type)})
                      </div>
                    </div>
                  ))}
                {hasMore && <span>...</span>}
              </div>
            )}
          >
            <Chip
              size='small'
              label={countLabel}
              sx={{ width: 100, borderRadius: 1 }}
            />
          </Tooltip>
        );
      },
    },
    createdBy: {
      isSortable: isRuntimeSort,
      percentWidth: 10,
    },
    creator: {
      isSortable: isRuntimeSort,
      percentWidth: 10,
    },
    created: {
      percentWidth: 13,
    },
    x_opencti_workflow_id: {},
    objectMarking: {
      isSortable: isRuntimeSort,
      percentWidth: 10,
    },
  };

  return (
    <>
      <Alert
        severity="info"
        variant="outlined"
        sx={{ marginBottom: 3 }}
      >
        {t_i18n('Pir analyses disclaimer...')}
      </Alert>
      {queryRef && (
        <div style={{ height: 'calc(100vh - 250px)' }} ref={(r) => setRef(r)}>
          <DataTable
            rootRef={ref ?? undefined}
            removeSelectAll
            disableLineSelection
            dataColumns={dataColumns}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            contextFilters={filters}
            lineFragment={pirAnalysesContainerFragment}
            entityTypes={['Container']}
            searchContextFinal={{ entityTypes: ['Container'] }}
            resolvePath={(d: PirAnalyses_ContainersFragment$data) => {
              return d.pir?.pirContainers?.edges?.map((e) => e?.node);
            }}
            preloadedPaginationProps={{
              linesQuery: pirAnalysesContainersListQuery,
              linesFragment: pirAnalysesContainersFragment,
              queryRef,
              nodePath: ['pir', 'pirContainers', 'pageInfo', 'globalCount'],
              setNumberOfElements: helpers.handleSetNumberOfElements,
            }}
          />
        </div>
      )}
    </>
  );
};

export default PirAnalyses;
