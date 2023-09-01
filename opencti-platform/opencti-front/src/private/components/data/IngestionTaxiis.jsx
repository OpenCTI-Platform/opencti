import React from 'react';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import IngestionTaxiiLines, {
  IngestionTaxiiLinesQuery,
} from './ingestionTaxii/IngestionTaxiiLines';
import IngestionTaxiiCreation from './ingestionTaxii/IngestionTaxiiCreation';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useAuth from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../../components/i18n';
import { INGESTION_MANAGER } from '../../../utils/platformModulesHelper';
import IngestionMenu from './IngestionMenu';

const LOCAL_STORAGE_KEY = 'ingestionTaxii-view';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const IngestionTaxii = () => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { platformModuleHelpers } = useAuth();
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
      width: '20%',
      isSortable: true,
    },
    uri: {
      label: 'URL',
      width: '30%',
      isSortable: true,
    },
    version: {
      label: 'Version',
      width: '10%',
      isSortable: true,
    },
    ingestion_running: {
      label: 'Running',
      width: '15%',
      isSortable: false,
    },
    added_after_start: {
      label: 'Current state',
      width: '15%',
      isSortable: false,
    },
  };
  if (!platformModuleHelpers.isIngestionManagerEnable()) {
    return (
      <Alert severity="info">
        {t(platformModuleHelpers.generateDisableMessage(INGESTION_MANAGER))}
      </Alert>
    );
  }
  return (
    <div className={classes.container}>
      <IngestionMenu />
      <ListLines
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
          query={IngestionTaxiiLinesQuery}
          variables={{ count: 200, ...paginationOptions }}
          render={({ props }) => (
            <IngestionTaxiiLines
              data={props}
              paginationOptions={paginationOptions}
              refetchPaginationOptions={{ count: 200, ...paginationOptions }}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
      <IngestionTaxiiCreation paginationOptions={paginationOptions} />
    </div>
  );
};

export default IngestionTaxii;
