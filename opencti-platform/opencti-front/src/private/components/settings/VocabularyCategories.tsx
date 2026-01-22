import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import ListLines from '../../../components/list_lines/ListLines';
import { useFormatter } from '../../../components/i18n';
import LabelsVocabulariesMenu from './LabelsVocabulariesMenu';
import { useVocabularyCategoryAsQuery, VocabularyDefinition } from '../../../utils/hooks/useVocabularyCategory';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import { VocabularyCategoryLine, VocabularyCategoryLineDummy } from './attributes/VocabularyCategoryLine';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

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

const VocabularyCategories = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Vocabularies | Taxonomies | Settings'));
  const { categories, sortBy, orderAsc, searchTerm, handleSort, handleSearch } = useVocabularyCategoryAsQuery();
  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '20%',
        isSortable: true,
        render: (node: VocabularyDefinition) => node.key,
      },
      entity_types: {
        label: 'Used in',
        width: '20%',
        isSortable: false,
        render: (node: VocabularyDefinition) => (
          <>
            {node.entity_types.map((type) => (
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
      description: {
        label: t_i18n('Description'),
        width: '45%',
        isSortable: false,
        render: (node: VocabularyDefinition) => {
          if (node.description) {
            return t_i18n(node.description);
          }
          return null;
        },
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={handleSort}
        handleSearch={handleSearch}
        displayImport={false}
        keyword={searchTerm}
      >
        <ListLinesContent
          initialLoading={false}
          loadMore={() => {}}
          hasMore={() => {}}
          isLoading={() => false}
          dataList={categories}
          globalCount={categories.length}
          LineComponent={VocabularyCategoryLine}
          DummyLineComponent={VocabularyCategoryLineDummy}
          dataColumns={dataColumns}
        />
      </ListLines>
    );
  };
  return (
    <div className={classes.container} data-testid="vocabularies-page">
      <LabelsVocabulariesMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Taxonomies') }, { label: t_i18n('Vocabularies'), current: true }]} />
      {renderLines()}
    </div>
  );
};

export default VocabularyCategories;
