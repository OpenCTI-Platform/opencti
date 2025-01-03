import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import IngestionTaxiiCollectionLines, { IngestionTaxiiCollectionLinesQuery } from './ingestionTaxiiCollection/IngestionTaxiiCollectionLines';
import IngestionTaxiiCollectionCreation from './ingestionTaxiiCollection/IngestionTaxiiCollectionCreation';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../components/i18n';
import IngestionMenu from './IngestionMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';
import Security from '../../../utils/Security';
import { INGESTION_SETINGESTIONS } from '../../../utils/hooks/useGranted';

const LOCAL_STORAGE_KEY = 'ingestionTaxii';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const IngestionTaxiiCollections = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage(LOCAL_STORAGE_KEY, {
    sortBy: 'name',
    orderAsc: false,
    searchTerm: '',
  });
  const dataColumns = {
    name: {
      label: 'Name',
      width: '15%',
      isSortable: true,
    },
    id: {
      label: 'Push Collection URI',
      width: '65%',
      isSortable: false,
    },
    ingestion_running: {
      label: 'Status',
      width: '10%',
      isSortable: false,
    },
  };
  return (
    <div className={classes.container}>
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('TAXII push'), current: true }]} />
      <IngestionMenu/>
      <ListLines
        helpers={storageHelpers}
        sortBy={viewStorage.sortBy}
        orderAsc={viewStorage.orderAsc}
        dataColumns={dataColumns}
        handleSort={storageHelpers.handleSort}
        handleSearch={storageHelpers.handleSearch}
        displayImport={false}
        secondaryAction={true}
        keyword={viewStorage.searchTerm}
      >
        <QueryRenderer
          query={IngestionTaxiiCollectionLinesQuery}
          variables={{ count: 200, ...paginationOptions }}
          render={({ props }) => (
            <IngestionTaxiiCollectionLines
              data={props}
              paginationOptions={paginationOptions}
              refetchPaginationOptions={{ count: 200, ...paginationOptions }}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
      <Security needs={[INGESTION_SETINGESTIONS]}>
        <IngestionTaxiiCollectionCreation paginationOptions={paginationOptions} />
      </Security>
    </div>
  );
};

export default IngestionTaxiiCollections;
