import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import LabelPopover from './labels/LabelPopover';
import LabelCreation from './labels/LabelCreation';
import LabelsVocabulariesMenu from './LabelsVocabulariesMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../components/i18n';
import DataTable from '../../../components/dataGrid/DataTable';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';

const useStyles = makeStyles((theme) => ({
  container: {
    margin: 0,
    padding: `0 calc( 200px - ${theme.spacing(3)} + ${theme.spacing(1)} ) 0 0`, // 200 of menu size, 3 space from main html, 1 for correct alignment
    maxWidth: '100%',
  },
}));

const LOCAL_STORAGE_KEY = 'Labels';

const labelsLinesQuery = graphql`
  query LabelsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: LabelsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...LabelsLines_data
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

const linesFragment = graphql`
  fragment LabelsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "LabelsOrdering", defaultValue: value }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "LabelsLinesRefetchPaginationQuery"){
    labels(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_labels")
    {
      edges {
        node {
          id
          entity_type
          ...LabelsLine_node
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

const lineFragment = graphql`
  fragment LabelsLine_node on Label {
    id
    entity_type
    value
    color
    created_at
    editContext {
      name
      focusOn
    }
  }
`;

const Labels = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Labels | Taxonomies | Settings'));
  const initialValues = {
    sortBy: 'value',
    orderAsc: true,
    searchTerm: '',
    openExports: false,
    filters: emptyFilterGroup,
  };

  const {
    helpers,
    paginationOptions,
    viewStorage: { filters },
  } = usePaginationLocalStorage(LOCAL_STORAGE_KEY, initialValues);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Label', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  };

  const dataColumns = {
    value: {
      label: 'Value',
      percentWidth: 50,
      isSortable: true,
    },
    color: {},
    created_at: {
      label: 'Platform creation date',
      percentWidth: 25,
      isSortable: true,
    },
  };

  const queryRef = useQueryLoading(
    labelsLinesQuery,
    queryPaginationOptions,
  );
  const preloadedPaginationProps = {
    linesQuery: labelsLinesQuery,
    linesFragment,
    queryRef,
    nodePath: ['labels', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  };

  return (
    <div className={classes.container}>
      <LabelsVocabulariesMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Taxonomies') }, { label: t_i18n('Labels'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.labels?.edges?.map((e) => e?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          lineFragment={lineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          actions={(label) => <LabelPopover label={label} paginationOptions={queryPaginationOptions} />}
          searchContextFinal={{ entityTypes: ['Label'] }}
          disableNavigation
        />
      )}
      <LabelCreation paginationOptions={queryPaginationOptions} />
    </div>
  );
};

Labels.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  navigate: PropTypes.func,
  location: PropTypes.object,
};

export default Labels;
