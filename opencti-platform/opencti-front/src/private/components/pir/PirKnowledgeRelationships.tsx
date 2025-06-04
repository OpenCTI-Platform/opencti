import { graphql } from 'react-relay';
import React from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { LibraryBooksOutlined } from '@mui/icons-material';
import { RelationManyToMany } from 'mdi-material-ui';
import {
  PirKnowledgeRelationshipsSourcesFlaggedListQuery,
  PirKnowledgeRelationshipsSourcesFlaggedListQuery$variables,
} from '@components/pir/__generated__/PirKnowledgeRelationshipsSourcesFlaggedListQuery.graphql';
import { PirKnowledgeRelationships_SourcesFlaggedFragment$data } from '@components/pir/__generated__/PirKnowledgeRelationships_SourcesFlaggedFragment.graphql';
import { PirKnowledgeRelationships_SourceFlaggedFragment$data } from '@components/pir/__generated__/PirKnowledgeRelationships_SourceFlaggedFragment.graphql';
import { useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { PaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../components/dataGrid/DataTable';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import { computeLink } from '../../../utils/Entity';
import FilterIconButton from '../../../components/FilterIconButton';
import { useFormatter } from '../../../components/i18n';
import { PaginationOptions } from '../../../components/list_lines';
import { LocalStorage } from '../../../utils/hooks/useLocalStorageModel';
import ItemEntityType from '../../../components/ItemEntityType';
import useAuth from '../../../utils/hooks/useAuth';

const sourceFlaggedFragment = graphql`
  fragment PirKnowledgeRelationships_SourceFlaggedFragment on StixRefRelationship {
    id
    pir_score
    pir_explanations {
      criterion {
        filters
      }
    }
    created_at
    to {
      ...on Pir {
        name
      }
    }
    from {
      ...on StixCoreObject {
        id
        entity_type
        created_at
        representative {
          main
        }
        objectLabel {
          id
          color
          value
        }
        creators {
          id
          name
        }
      }
    }
  }
`;

const sourcesFlaggedFragment = graphql`
  fragment PirKnowledgeRelationships_SourcesFlaggedFragment on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixRefRelationshipsOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    toId: { type: "StixRef" }
    relationship_type: { type: "[String]" }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PirsKnowledgeRelationships_SourcesFlaggedRefetchQuery") {
    stixRefRelationships(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      toId: $toId
      relationship_type: $relationship_type
      filters: $filters
    ) @connection(key: "PaginationPirKnowledgeRelationships_stixRefRelationships") {
      edges {
        node {
          id
          ...PirKnowledgeRelationships_SourceFlaggedFragment
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

const sourcesFlaggedListQuery = graphql`
  query PirKnowledgeRelationshipsSourcesFlaggedListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixRefRelationshipsOrdering
    $orderMode: OrderingMode
    $toId: StixRef
    $relationship_type: [String]
    $filters: FilterGroup
  ) {
    ...PirKnowledgeRelationships_SourcesFlaggedFragment
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      toId: $toId
      relationship_type: $relationship_type
      filters: $filters
    )
  }
`;

interface PirKnowledgeRelationshipsProps {
  pirId: string;
  localStorage: PaginationLocalStorage<PaginationOptions>;
  initialValues: LocalStorage;
}

const PirKnowledgeRelationships = ({ pirId, localStorage, initialValues }: PirKnowledgeRelationshipsProps) => {
  const { t_i18n } = useFormatter();
  const {
    viewStorage,
    helpers,
    localStorageKey,
    paginationOptions,
  } = localStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext(
    'in-pir',
    viewStorage.filters,
    undefined,
    ['stix-ref-relationship'],
  );
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
    relationship_type: ['in-pir'],
    toId: pirId,
  } as unknown as PirKnowledgeRelationshipsSourcesFlaggedListQuery$variables;

  const queryRef = useQueryLoading<PirKnowledgeRelationshipsSourcesFlaggedListQuery>(
    sourcesFlaggedListQuery,
    queryPaginationOptions,
  );

  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const dataColumns: DataTableProps['dataColumns'] = {
    pirScore: {
      id: 'pir_score',
      label: 'Score',
      percentWidth: 5,
      isSortable: true,
      render: ({ pir_score }) => defaultRender(`${pir_score}%`),
    },
    fromType: {
      id: 'fromType',
      label: 'From type',
      percentWidth: 10,
      isSortable: false,
      render: (node) => (
        <ItemEntityType inList showIcon entityType={node.from?.entity_type} isRestricted={!node.from} />
      ),
    },
    fromName: {
      percentWidth: 25,
    },
    toType: {
      id: 'toType',
      label: 'To type',
      percentWidth: 7,
      isSortable: false,
      render: () => (
        <ItemEntityType inList showIcon entityType={'Pir'} />
      ),
    },
    toName: {
      percentWidth: 7,
    },
    created_at: { percentWidth: 10 },
    objectMarking: { isSortable: isRuntimeSort },
    pirCriteria: {
      id: 'explanations',
      label: 'Explanations',
      percentWidth: 28,
      render: ({ pir_explanations }) => (
        <div style={{ display: 'flex' }}>
          {pir_explanations.map((e: { criterion: { filters: string } }) => (
            <FilterIconButton
              key={e.criterion.filters}
              filters={JSON.parse(e.criterion.filters)}
              entityTypes={['Stix-Core-Object']}
              styleNumber={3}
            />
          ))}
        </div>
      ),
    },
  };

  return (
    <>
      {queryRef && (
        <DataTable
          disableSelectAll
          disableLineSelection
          dataColumns={dataColumns}
          resolvePath={(d: PirKnowledgeRelationships_SourcesFlaggedFragment$data) => {
            return d.stixRefRelationships?.edges?.map((e) => e?.node);
          }}
          storageKey={localStorageKey}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={{
            linesQuery: sourcesFlaggedListQuery,
            linesFragment: sourcesFlaggedFragment,
            queryRef,
            nodePath: ['stixRefRelationships', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={sourceFlaggedFragment}
          availableFilterKeys={['fromId', 'fromTypes', 'pir_score']}
          entityTypes={['stix-ref-relationship']}
          searchContextFinal={{ entityTypes: ['stix-ref-relationship'] }}
          currentView={viewStorage.view}
          useComputeLink={(e: PirKnowledgeRelationships_SourceFlaggedFragment$data) => {
            if (!e.from || !e.from.id || !e.from.entity_type) return '';
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-ignore
            return computeLink(e.from);
          }}
          additionalHeaderButtons={[
            (<ToggleButton key="entities" value="entities" aria-label="entities">
              <Tooltip title={t_i18n('Entities view')}>
                <LibraryBooksOutlined fontSize="small" color="primary" />
              </Tooltip>
            </ToggleButton>),
            (<ToggleButton key="relationships" value="relationships" aria-label="relationships">
              <Tooltip title={t_i18n('Relationships view')}>
                <RelationManyToMany color="secondary" fontSize="small" />
              </Tooltip>
            </ToggleButton>),
          ]}
        />
      )}
    </>
  );
};

export default PirKnowledgeRelationships;
