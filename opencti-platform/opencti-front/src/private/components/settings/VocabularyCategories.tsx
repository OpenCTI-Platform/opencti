import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import { useTheme } from '@mui/styles';
import ListLines from '../../../components/list_lines/ListLines';
import { hexToRGB } from '../../../utils/Colors';
import { useFormatter } from '../../../components/i18n';
import { Theme } from '../../../components/Theme';
import LabelsVocabulariesMenu from './LabelsVocabulariesMenu';
import { useVocabularyCategoryAsQuery, VocabularyDefinition } from '../../../utils/hooks/useVocabularyCategory';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import { VocabularyCategoryLine, VocabularyCategoryLineDummy } from './attributes/VocabularyCategoryLine';

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
  const { t } = useFormatter();
  const theme = useTheme<Theme>();

  const {
    categories,
    sortBy,
    orderAsc,
    searchTerm,
    handleSort,
    handleSearch,
  } = useVocabularyCategoryAsQuery();

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
      description: {
        label: 'Description',
        width: '45%',
        isSortable: true,
        render: (node: VocabularyDefinition) => node.description,
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
        secondaryAction={true}
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
    <div className={classes.container}>
      <LabelsVocabulariesMenu />
      {renderLines()}
    </div>
  );
};

export default VocabularyCategories;
