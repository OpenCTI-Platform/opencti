import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { graphql } from 'react-relay';
import { NotesLines_data$data } from '@components/analyses/__generated__/NotesLines_data.graphql';
import { NotesLinesPaginationQuery, NotesLinesPaginationQuery$variables } from '@components/analyses/__generated__/NotesLinesPaginationQuery.graphql';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import NoteCreation from './notes/NoteCreation';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const LOCAL_STORAGE_KEY = 'notes';

const notesLineFragment = graphql`
  fragment NotesLine_node on Note {
    id
    entity_type
    attribute_abstract
    content
    created
    note_types
    likelihood
    confidence
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    creators {
      id
      name
    }
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
  }
`;

const notesLinesQuery = graphql`
  query NotesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: NotesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...NotesLines_data
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

const notesLinesFragment = graphql`
  fragment NotesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "NotesOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "NotesLinesRefetchQuery") {
    notes(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_notes") {
      edges {
        node {
          id
          attribute_abstract
          content
          created
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...NotesLine_node
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

const Notes: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Notes | Analyses'));
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const initialValues = {
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['note_types'], ['Note']),
    },
  };

  const {
    viewStorage,
    helpers: storageHelpers,
    paginationOptions,
  } = usePaginationLocalStorage<NotesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Note', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as NotesLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<NotesLinesPaginationQuery>(
    notesLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    attribute_abstract: {},
    note_types: {},
    createdBy: { isSortable: isRuntimeSort },
    creator: { isSortable: isRuntimeSort },
    objectLabel: {},
    created: { percentWidth: 10 },
    x_opencti_workflow_id: {},
    objectMarking: { isSortable: isRuntimeSort },
  };

  const preloadedPaginationProps = {
    linesQuery: notesLinesQuery,
    linesFragment: notesLinesFragment,
    queryRef,
    nodePath: ['notes', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<NotesLinesPaginationQuery>;

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Notes'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: NotesLines_data$data) => data.notes?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={notesLineFragment}
          exportContext={{ entity_type: 'Note' }}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
              <NoteCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
          <NoteCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </>
  );
};

export default Notes;
