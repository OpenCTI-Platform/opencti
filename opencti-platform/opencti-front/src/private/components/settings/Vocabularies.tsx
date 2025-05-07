import React from 'react';
import Chip from '@mui/material/Chip';
import { useParams } from 'react-router-dom';
import { graphql } from 'react-relay';
import { ShortTextOutlined } from '@mui/icons-material';
import VocabularyPopover from '@components/settings/attributes/VocabularyPopover';
import { VocabulariesLinesPaginationQuery, VocabulariesLinesPaginationQuery$variables } from '@components/settings/__generated__/VocabulariesLinesPaginationQuery.graphql';
import { useTheme } from '@mui/material';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useVocabularyCategory_Vocabularynode$data } from '../../../utils/hooks/__generated__/useVocabularyCategory_Vocabularynode.graphql';
import { useFormatter } from '../../../components/i18n';
import LabelsVocabulariesMenu from './LabelsVocabulariesMenu';
import VocabularyCreation from './attributes/VocabularyCreation';
import useVocabularyCategory, { vocabFragment } from '../../../utils/hooks/useVocabularyCategory';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';

export const vocabulariesQuery = graphql`
  query VocabulariesLinesPaginationQuery(
    $search: String
    $count: Int
    $orderMode: OrderingMode
    $orderBy: VocabularyOrdering
    $filters: FilterGroup
    $category: VocabularyCategory
  ) {
    ...VocabulariesLines_data
    @arguments(
      search: $search
      count: $count
      orderMode: $orderMode
      orderBy: $orderBy
      filters: $filters
      category: $category
    )
  }
`;

export const vocabulariesFragment = graphql`
  fragment VocabulariesLines_data on Query
  @argumentDefinitions(
    filters: { type: "FilterGroup" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 200 }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    orderBy: { type: "VocabularyOrdering", defaultValue: name }
    after: { type: "ID" }
    category: { type: "VocabularyCategory" }
  )
  @refetchable(queryName: "VocabulariesLines_DataQuery") {
    vocabularies(
      filters: $filters
      search: $search
      first: $count
      orderMode: $orderMode
      orderBy: $orderBy
      after: $after
      category: $category
    ) @connection(key: "Pagination_vocabularies") {
      edges {
        node {
          id
          ...useVocabularyCategory_Vocabularynode
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

const Vocabularies = () => {
  const { t_i18n, n } = useFormatter();
  const theme = useTheme();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Vocabularies | Taxonomies | Settings'));
  const params = useParams() as { category: string };
  const { typeToCategory } = useVocabularyCategory();
  const category = typeToCategory(params.category);
  const LOCAL_STORAGE_KEY = `vocabulary-${category}`;

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    filters: emptyFilterGroup,
    category,
  };

  const {
    viewStorage,
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage<VocabulariesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('Vocabulary', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as VocabulariesLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<VocabulariesLinesPaginationQuery>(
    vocabulariesQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      label: 'Name',
      percentWidth: 20,
      isSortable: true,
      render: (node: useVocabularyCategory_Vocabularynode$data) => node.name,
    },
    entity_types: {
      label: 'Used in',
      percentWidth: 20,
      isSortable: false,
      render: (node: useVocabularyCategory_Vocabularynode$data) => (
        <>
          {node.category.entity_types.map((type) => (
            <Chip
              key={type}
              style={{
                fontSize: 12,
                height: 20,
                float: 'left',
                marginRight: 7,
              }}
              variant="outlined"
              label={t_i18n(`entity_${type}`)}
              color="primary"
            />
          ))}
        </>
      ),
    },
    aliases: {
      label: 'Aliases',
      percentWidth: 15,
      isSortable: false,
      render: (node: useVocabularyCategory_Vocabularynode$data) => (node.aliases ?? []).join(', '),
    },
    description: {
      label: 'Description',
      percentWidth: 25,
      isSortable: false,
      render: (node: useVocabularyCategory_Vocabularynode$data) => node.description,
    },
    usages: {
      label: 'Usages',
      percentWidth: 10,
      isSortable: false,
      render: (node: useVocabularyCategory_Vocabularynode$data) => n(node.usages),
    },
    order: {
      label: 'Order',
      percentWidth: 10,
      isSortable: true,
      render: (node: useVocabularyCategory_Vocabularynode$data) => n(node.order),
    },
  };

  const preloadedPaginationProps = {
    linesQuery: vocabulariesQuery,
    linesFragment: vocabulariesFragment,
    queryRef,
    nodePath: ['vocabularies', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<VocabulariesLinesPaginationQuery>;

  return (
    <div style={{ marginRight: 200 }}>
      <LabelsVocabulariesMenu />
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Taxonomies') },
        { label: t_i18n('Vocabularies'), link: '/dashboard/settings/vocabularies/fields' },
        { label: category, current: true }]}
      />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.vocabularies?.edges?.map(({ node }: { node: useVocabularyCategory_Vocabularynode$data }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          lineFragment={vocabFragment}
          disableNavigation
          preloadedPaginationProps={preloadedPaginationProps}
          actions={(vocab) => <VocabularyPopover vocab={vocab} paginationOptions={paginationOptions} />}
          searchContextFinal={{ entityTypes: ['Vocabulary'] }}
          icon={() => <ShortTextOutlined sx={{ color: theme.palette.primary.main }} />}
          createButton={<VocabularyCreation
            category={category}
            paginationOptions={paginationOptions}
                        />}
        />
      )}
    </div>
  );
};

export default Vocabularies;
