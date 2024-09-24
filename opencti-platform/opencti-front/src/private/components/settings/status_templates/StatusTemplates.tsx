import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ListLines from '../../../../components/list_lines/ListLines';
import StatusTemplateCreation from './StatusTemplateCreation';
import StatusTemplatesLines, { statusTemplatesLinesQuery } from './StatusTemplatesLines';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import StatusTemplateLineDummy from './StatusTemplateLineDummy';
import { StatusTemplatesLinesPaginationQuery, StatusTemplatesLinesPaginationQuery$variables } from './__generated__/StatusTemplatesLinesPaginationQuery.graphql';
import LabelsVocabulariesMenu from '../LabelsVocabulariesMenu';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const LOCAL_STORAGE_KEY = 'status-templates';

const StatusTemplates = () => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<StatusTemplatesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
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
        width: '50%',
        isSortable: true,
      },
      color: {
        label: 'Color',
        width: '30%',
        isSortable: false,
      },
      usages: {
        label: 'Usages',
        width: '20%',
        isSortable: false,
      },
    };
    const queryRef = useQueryLoading<StatusTemplatesLinesPaginationQuery>(
      statusTemplatesLinesQuery,
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
        secondaryAction={false}
        keyword={searchTerm}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <StatusTemplateLineDummy
                      key={idx}
                      dataColumns={dataColumns}
                    />
                  ))}
              </>
            }
          >
            <StatusTemplatesLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              setNumberOfElements={helpers.handleSetNumberOfElements}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };
  return (
    <div className={classes.container}>
      <LabelsVocabulariesMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Taxonomies') }, { label: t_i18n('Status templates'), current: true }]} />
      {renderLines()}
      <StatusTemplateCreation
        paginationOptions={paginationOptions}
        contextual={false}
        creationCallback={() => {}}
        handleCloseContextual={() => {}}
        inputValueContextual={''}
        openContextual={false}
      />
    </div>
  );
};

export default StatusTemplates;
