import React, { useState } from 'react';
import Grid from '@mui/material/Grid';
import TextField from '@mui/material/TextField';
import { Link } from 'react-router-dom';
import Chip from '@mui/material/Chip';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/styles';
import { allEntitiesKeyList } from './common/bulk/utils/querySearchEntityByText';
import { useFormatter } from '../../components/i18n';
import { resolveLink } from '../../utils/Entity';
import Breadcrumbs from '../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../utils/hooks/useConnectedDocumentModifier';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import DataTable from '../../components/dataGrid/DataTable';
import { addFilter, emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';

const searchBulkLineFragment = graphql`
  fragment SearchBulkLine_node on StixCoreObject {
    id
    entity_type
    created_at
    updated_at
    draftVersion {
      draft_id
      draft_operation
    }
    ... on StixObject {
      representative {
        main
        secondary
      }
    }
    ... on HashedObservable {
      hashes {
        algorithm
        hash
      }
    }
    createdBy {
      ... on Identity {
        name
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
    containersNumber {
      total
    }
  }
`;

export const searchBulkQuery = graphql`
  query SearchBulkQuery(
    $count: Int!
    $cursor: ID
    $types: [String]
    $filters: FilterGroup
    $search: String
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...SearchBulkQuery_data
    @arguments(
      count: $count
      cursor: $cursor
      types: $types
      filters: $filters
      search: $search
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

export const searchBulkFragment = graphql`
  fragment SearchBulkQuery_data on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 500 }
    cursor: { type: "ID" }
    types: { type: "[String]" }
    search: { type: "String" }
    filters: { type: "FilterGroup" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: entity_type }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  )
  @refetchable(queryName: "SearchBulkRefetchQuery") {
    globalSearch(
      first: $count
      after: $cursor
      types: $types,
      search: $search,
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    )
    @connection(key: "Pagination_globalSearch") {
      edges {
        node {
          id
          entity_type
          ...SearchBulkLine_node
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

const buildQueryParams = (textFieldValue, filters) => {
  const values = textFieldValue
    .split('\n')
    .filter((o) => o.length > 1)
    .map((val) => val.trim());
  const queryFilters = values.length > 0
    ? addFilter(filters, allEntitiesKeyList, values)
    : filters;
  return { values, queryFilters, count: 5000 };
};

const LOCAL_STORAGE_KEY = 'search_bulk';

const SearchBulk = () => {
  const { t_i18n, n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const theme = useTheme();

  setTitle(t_i18n('Bulk Search'));

  const [textFieldValue, setTextFieldValue] = useState('');

  const initialValues = {
    searchTerm: '',
    sortBy: 'entity_type',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const { filters } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', filters);

  const { values, queryFilters, count } = buildQueryParams(textFieldValue, contextFilters);

  const queryPaginationOptions = { ...paginationOptions, filters: queryFilters, count };

  const queryRef = useQueryLoading(searchBulkQuery, queryPaginationOptions);

  const preloadedPaginationProps = {
    linesQuery: searchBulkQuery,
    linesFragment: searchBulkFragment,
    queryRef,
    nodePath: ['globalSearch', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  };

  const handleChangeTextField = (event) => {
    const { value } = event.target;
    setTextFieldValue(
      value
        .split('\n')
        .map((o) => o
          .split(',')
          .map((p) => p.split(';'))
          .flat())
        .flat()
        .join('\n'),
    );
  };

  const dataColumns = {
    entity_type: {
      isSortable: true,
    },
    value: {
      isSortable: true,
    },
    createdBy: {},
    creators: {},
    objectLabel: {},
    created_at: {},
    analyses: {
      id: 'analyses',
      label: 'Analyses',
      isSortable: false,
      render: ({ id, entity_type, containersNumber }) => {
        const analysesNumber = containersNumber?.total;
        const link = `${resolveLink(entity_type)}/${id}`;
        const linkAnalyses = `${link}/analyses`;
        return (
          <>
            {['Note', 'Opinion', 'Course-Of-Action', 'Data-Component', 'Data-Source'].includes(entity_type) ? (
              <Chip
                style={{
                  fontSize: 13,
                  lineHeight: '12px',
                  height: 20,
                  textTransform: 'uppercase',
                  borderRadius: 4,
                }}
                label={n(analysesNumber)}
              />
            ) : (
              <Chip
                style={{
                  fontSize: 13,
                  lineHeight: '12px',
                  height: 20,
                  textTransform: 'uppercase',
                  borderRadius: 4,
                  cursor: 'pointer',
                  '&:hover': {
                    backgroundColor: theme.palette.primary.main,
                  },
                }}
                label={n(analysesNumber)}
                component={Link}
                to={linkAnalyses}
              />
            )}
          </>
        );
      },
    },
    objectMarking: {},
  };

  return (
    <>
      <Breadcrumbs variant="standard" elements={[{ label: t_i18n('Search') }, { label: t_i18n('Bulk search'), current: true }]} />
      <div className="clearfix" />
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20, marginTop: 0 }}
      >
        <Grid item xs={2} style={{ marginTop: -20 }}>
          <TextField
            onChange={handleChangeTextField}
            value={textFieldValue}
            multiline={true}
            fullWidth={true}
            minRows={20}
            placeholder={t_i18n('One keyword by line or separated by commas')}
            variant="outlined"
          />
        </Grid>
        <Grid item xs={10} style={{ marginTop: -20 }}>
          {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data) => data.globalSearch?.edges?.map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            toolbarFilters={queryFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            exportContext={{ entity_type: 'Stix-Core-Object' }}
            paginationOptions={queryPaginationOptions}
            lineFragment={searchBulkLineFragment}
            hideSearch
            disableToolBar
            disableLineSelection
          />
          )}
        </Grid>
      </Grid>
    </>
  );
};

export default SearchBulk;
