import React, { useEffect } from 'react';
import { useTheme } from '@mui/material';
import { useFormatter } from '../../../components/i18n';
import LabelsVocabulariesMenu from './LabelsVocabulariesMenu';
import { useVocabularyCategoryAsQuery, VocabularyDefinition } from '../../../utils/hooks/useVocabularyCategory';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import DataTableWithoutFragment from '../../../components/dataGrid/DataTableWithoutFragment';
import { ShortTextOutlined } from '@mui/icons-material';
import SearchInput from '../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';

const LOCAL_STORAGE_KEY = 'vocabulary_categories';

const VocabularyCategories = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const theme = useTheme();

  setTitle(t_i18n('Vocabularies | Taxonomies | Settings'));

  const { categories, sortBy: sortByVocabularyCategory, orderAsc: orderAscVocabularyCategory, searchTerm, handleSearch, handleSort } = useVocabularyCategoryAsQuery();

  const { viewStorage, helpers } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      sortBy: 'name',
      orderAsc: true,
    },
  );
  const { sortBy = 'name', orderAsc = true } = viewStorage;

  // Sync local storage sorting with hook sorting
  useEffect(() => {
    if (sortBy !== sortByVocabularyCategory || orderAsc !== orderAscVocabularyCategory) {
      handleSort(sortBy, orderAsc);
    }
  }, [sortBy, orderAsc, sortByVocabularyCategory, orderAscVocabularyCategory, handleSort]);

  const onSort = (field: string, order: boolean) => {
    handleSort(field, order);
    helpers.handleSort(field, order);
  };

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      percentWidth: 20,
      isSortable: true,
      render: (data: { category: VocabularyDefinition }) => data.category.key,
    },
    entity_types: {
      id: 'entity_types',
      percentWidth: 20,
      isSortable: true,
    },
    description: {
      id: 'description',
      percentWidth: 60,
      isSortable: false,
      render: (data: { category: VocabularyDefinition }) => (data.category.description ? t_i18n(data.category.description) : ''),
    },
  };

  return (
    <div style={{ paddingRight: 200 }} data-testid="vocabularies-page">
      <LabelsVocabulariesMenu />
      <Breadcrumbs
        elements={[
          { label: t_i18n('Settings') },
          { label: t_i18n('Taxonomies') },
          { label: t_i18n('Vocabularies'), current: true },
        ]}
      />
      <div>
        <SearchInput
          variant="small"
          onSubmit={handleSearch}
          keyword={searchTerm}
          style={{ marginBottom: theme.spacing(2) }}
        />
        <DataTableWithoutFragment
          storageKey={LOCAL_STORAGE_KEY}
          isLocalStorageEnabled={false}
          data={categories.map(({ node }) => ({ category: node }))}
          dataColumns={dataColumns}
          getComputeLink={({ category }: { category: VocabularyDefinition }) => (category.key)}
          globalCount={categories.length}
          icon={() => (<ShortTextOutlined color="primary" />)}
          onSort={onSort}
        />
      </div>
    </div>
  );
};

export default VocabularyCategories;
