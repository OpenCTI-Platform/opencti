import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import { useParams } from 'react-router-dom';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import VocabulariesLines, { vocabulariesLinesQuery } from './attributes/VocabulariesLines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { VocabulariesLines_DataQuery$variables } from './attributes/__generated__/VocabulariesLines_DataQuery.graphql';
import { VocabulariesLinesPaginationQuery } from './attributes/__generated__/VocabulariesLinesPaginationQuery.graphql';
import { useVocabularyCategory_Vocabularynode$data } from '../../../utils/hooks/__generated__/useVocabularyCategory_Vocabularynode.graphql';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import LabelsVocabulariesMenu from './LabelsVocabulariesMenu';
import VocabularyCreation from './attributes/VocabularyCreation';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import ToolBar from '../data/ToolBar';
import useVocabularyCategory from '../../../utils/hooks/useVocabularyCategory';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  label: {
    fontSize: 12,
    height: 20,
    float: 'left',
    marginRight: 7,
  },
}));

const Vocabularies = () => {
  const classes = useStyles();
  const { t_i18n, n } = useFormatter();
  const params = useParams() as { category: string };
  const { typeToCategory } = useVocabularyCategory();
  const category = typeToCategory(params.category);
  const LOCAL_STORAGE_KEY = `vocabulary-${category}`;

  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage<VocabulariesLines_DataQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: emptyFilterGroup,
      sortBy: 'name',
      orderAsc: true,
      searchTerm: '',
      category,
    },
  );
  const queryRef = useQueryLoading<VocabulariesLinesPaginationQuery>(
    vocabulariesLinesQuery,
    paginationOptions,
  );
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<useVocabularyCategory_Vocabularynode$data>(
    LOCAL_STORAGE_KEY,
  );
  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '20%',
        isSortable: true,
        render: (node: useVocabularyCategory_Vocabularynode$data) => node.name,
      },
      entity_types: {
        label: 'Used in',
        width: '20%',
        isSortable: false,
        render: (node: useVocabularyCategory_Vocabularynode$data) => (
          <>
            {node.category.entity_types.map((type) => (
              <Chip
                key={type}
                classes={{ root: classes.label }}
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
        width: '15%',
        isSortable: false,
        render: (node: useVocabularyCategory_Vocabularynode$data) => (node.aliases ?? []).join(', '),
      },
      description: {
        label: 'Description',
        width: '25%',
        isSortable: false,
        render: (node: useVocabularyCategory_Vocabularynode$data) => node.description,
      },
      usages: {
        label: 'Usages',
        width: '10%',
        isSortable: false,
        render: (node: useVocabularyCategory_Vocabularynode$data) => n(node.usages),
      },
      order: {
        label: 'Order',
        width: '10%',
        isSortable: true,
        render: (node: useVocabularyCategory_Vocabularynode$data) => n(node.order),
      },
    };
    const toolBarFilters = {
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Vocabulary'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    return (
      <ListLines
        sortBy={viewStorage.sortBy}
        iconExtension={true}
        orderAsc={viewStorage.orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        handleToggleSelectAll={handleToggleSelectAll}
        selectAll={selectAll}
        displayImport={false}
        secondaryAction={true}
        keyword={paginationOptions.search}
        filters={viewStorage.filters}
      >
        {queryRef && (
          <>
            <React.Suspense
              fallback={<Loader variant={LoaderVariant.inElement} />}
            >
              <VocabulariesLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={helpers.handleSetNumberOfElements}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
              />
            </React.Suspense>
            <ToolBar
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              numberOfSelectedElements={numberOfSelectedElements}
              handleClearSelectedElements={handleClearSelectedElements}
              selectAll={selectAll}
              noAuthor={true}
              noMarking={true}
              noWarning={true}
              deleteDisable={true}
              filters={toolBarFilters}
              variant="medium"
            />
          </>
        )}
      </ListLines>
    );
  };
  return (
    <div className={classes.container}>
      <LabelsVocabulariesMenu />
      <Breadcrumbs variant="list" elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Taxonomies') },
        { label: t_i18n('Vocabularies'), link: '/dashboard/settings/vocabularies/fields' },
        { label: category, current: true }]}
      />
      {renderLines()}
      <VocabularyCreation
        category={category}
        paginationOptions={paginationOptions}
      />
    </div>
  );
};

export default Vocabularies;
