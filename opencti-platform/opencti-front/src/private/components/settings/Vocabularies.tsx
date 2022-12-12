import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import { useTheme } from '@mui/styles';
import ListLines from '../../../components/list_lines/ListLines';
import useLocalStorage, { localStorageToPaginationOptions } from '../../../utils/hooks/useLocalStorage';
import VocabulariesLines, { vocabulariesLinesQuery } from './attributes/VocabulariesLines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { VocabulariesLines_DataQuery$variables } from './attributes/__generated__/VocabulariesLines_DataQuery.graphql';
import { VocabulariesLinesPaginationQuery } from './attributes/__generated__/VocabulariesLinesPaginationQuery.graphql';
import {
  useVocabularyCategory_Vocabularynode$data,
} from '../../../utils/hooks/__generated__/useVocabularyCategory_Vocabularynode.graphql';
import { hexToRGB } from '../../../utils/Colors';
import { useFormatter } from '../../../components/i18n';
import { Theme } from '../../../components/Theme';
import Loader, { LoaderVariant } from '../../../components/Loader';
import LabelsVocabulariesMenu from './LabelsVocabulariesMenu';
import VocabularyCreation from './attributes/VocabularyCreation';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import ToolBar from '../data/ToolBar';

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
  const { t } = useFormatter();
  const theme = useTheme<Theme>();

  const [
    viewStorage,
    _,
    {
      handleAddFilter,
      handleSort,
      handleSearch,
      handleRemoveFilter,
      handleSetNumberOfElements,
    },
  ] = useLocalStorage('view-vocabulary', {
    sortBy: 'name',
    orderAsc: true,
    searchTerm: '',
    numberOfElements: { number: 0, symbol: '', original: 0 },
  });

  const queryProps = localStorageToPaginationOptions<VocabulariesLines_DataQuery$variables>({
    ...viewStorage,
    count: 200,
  });
  const queryRef = useQueryLoading<VocabulariesLinesPaginationQuery>(vocabulariesLinesQuery, queryProps);

  const {
    onToggleEntity,
    selectAll,
    numberOfSelectedElements,
    handleClearSelectedElements,
    handleToggleSelectAll,
    selectedElements,
    deSelectedElements,
  } = useEntityToggle<useVocabularyCategory_Vocabularynode$data>('view-vocabulary');

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
                label={t(type)}
                style={{
                  color: theme.palette.chip.main,
                  borderColor: theme.palette.chip.main,
                  backgroundColor: hexToRGB('transparent'),
                }}
              />
            ))}
          </>
        ),
      },
      aliases: {
        label: 'Aliases',
        width: '10%',
        isSortable: false,
        render: (node: useVocabularyCategory_Vocabularynode$data) => (node.aliases ?? []).join(', '),
      },
      description: {
        label: 'Description',
        width: '45%',
        isSortable: true,
        render: (node: useVocabularyCategory_Vocabularynode$data) => node.description,
      },
      usages: {
        label: 'Usages',
        width: '5%',
        isSortable: false,
        render: (node: useVocabularyCategory_Vocabularynode$data) => node.usages.length,
      },
    };
    return (
      <ListLines
        sortBy={viewStorage.sortBy}
        orderAsc={viewStorage.orderAsc}
        dataColumns={dataColumns}
        handleSort={handleSort}
        handleSearch={handleSearch}
        handleAddFilter={handleAddFilter}
        handleRemoveFilter={handleRemoveFilter}
        handleToggleSelectAll={handleToggleSelectAll}
        selectAll={selectAll}
        displayImport={false}
        secondaryAction={true}
        keyword={queryProps.search}
        filters={viewStorage.filters}
        availableFilterKeys={[
          'entity_types',
          'category',
        ]}
      >
        {queryRef && (
          <>
            <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
              <VocabulariesLines
                queryRef={queryRef}
                paginationOptions={queryProps}
                dataColumns={dataColumns}
                setNumberOfElements={handleSetNumberOfElements}
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
              selectAll={selectAll}
              handleClearSelectedElements={handleClearSelectedElements}
              filters={{ entity_type: [{ id: 'Vocabulary' }] }}
              variant="large"
            />
          </>
        )}
      </ListLines>
    );
  };

  return (
    <div className={classes.container}>
      <LabelsVocabulariesMenu />
      {renderLines()}
      <VocabularyCreation paginationOptions={queryProps} />
    </div>
  );
};

export default Vocabularies;
