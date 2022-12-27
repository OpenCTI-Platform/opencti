import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ListLines from '../../../../components/list_lines/ListLines';
import StatusTemplateCreation from './StatusTemplateCreation';
import StatusTemplatesLines, { statusTemplatesLinesQuery } from './StatusTemplatesLines';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import StatusTemplateLineDummy from './StatusTemplateLineDummy';
import {
  StatusTemplatesLinesPaginationQuery,
  StatusTemplatesLinesPaginationQuery$variables,
} from './__generated__/StatusTemplatesLinesPaginationQuery.graphql';
import LabelsVocabulariesMenu from '../LabelsVocabulariesMenu';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const LOCAL_STORAGE_KEY = 'view-status-templates';

const StatusTemplates = () => {
  const classes = useStyles();

  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<StatusTemplatesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: false,
    },
  );

  const renderLines = () => {
    const {
      sortBy,
      orderAsc,
      searchTerm,
    } = viewStorage;
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
        width: '5%',
        isSortable: false,
      },
    };
    const queryRef = useQueryLoading<StatusTemplatesLinesPaginationQuery>(statusTemplatesLinesQuery, paginationOptions);

    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        displayImport={false}
        secondaryAction={false}
        keyword={searchTerm}>

        {queryRef && (
          <React.Suspense fallback={
            <>{Array(20).fill(0)
              .map((idx) => (<StatusTemplateLineDummy key={idx} dataColumns={dataColumns} />))}</>
          }>
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
      {renderLines()}
      <StatusTemplateCreation
        paginationOptions={paginationOptions}
        contextual={false}
        creationCallback={() => {}}
        handleCloseContextual={() => {}}
        inputValueContextual={''}
        openContextual={false} />
    </div>
  );
};

export default StatusTemplates;
