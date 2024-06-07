import makeStyles from '@mui/styles/makeStyles';
import React from 'react';
import ListLines from '../../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import LabelsVocabulariesMenu from '../LabelsVocabulariesMenu';
import { CaseTemplateLine_node$data } from './__generated__/CaseTemplateLine_node.graphql';
import { CaseTemplateLinesPaginationQuery, CaseTemplateLinesPaginationQuery$variables } from './__generated__/CaseTemplateLinesPaginationQuery.graphql';
import CaseTemplateCreation from './CaseTemplateCreation';
import CaseTemplateLineDummy from './CaseTemplateLineDummy';
import CaseTemplateLines, { caseTemplatesLinesQuery } from './CaseTemplateLines';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const LOCAL_STORAGE_KEY_CASE_TEMPLATES = 'case-templates';

const CaseTemplates = () => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CaseTemplateLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_CASE_TEMPLATES,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: false,
    },
  );

  const renderLines = () => {
    const { sortBy, orderAsc, searchTerm } = viewStorage;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '30%',
        isSortable: true,
        render: (data: CaseTemplateLine_node$data) => data.name,
      },
      description: {
        label: 'Description',
        width: '40%',
        isSortable: false,
        render: (data: CaseTemplateLine_node$data) => data.description,
      },
      tasks: {
        label: 'Tasks',
        width: '10%',
        isSortable: false,
        render: (data: CaseTemplateLine_node$data) => data.tasks.pageInfo.globalCount,
      },
    };
    const queryRef = useQueryLoading<CaseTemplateLinesPaginationQuery>(
      caseTemplatesLinesQuery,
      paginationOptions,
    );

    return (
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        displayImport={false}
        keyword={searchTerm}
      >
        {queryRef && (
          <>
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <CaseTemplateLineDummy
                        key={idx}
                        dataColumns={dataColumns}
                      />
                    ))}
                </>
              }
            >
              <CaseTemplateLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={helpers.handleSetNumberOfElements}
              />
            </React.Suspense>
          </>
        )}
      </ListLines>
    );
  };

  return (
    <div className={classes.container}>
      <LabelsVocabulariesMenu />
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Taxonomies') }, { label: t_i18n('Case templates'), current: true }]} />
      {renderLines()}
      <CaseTemplateCreation
        paginationOptions={paginationOptions}
      />
    </div>
  );
};

export default CaseTemplates;
