import React from 'react';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import SyncLines, { SyncLinesQuery } from './sync/SyncLines';
import SyncCreation from './sync/SyncCreation';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useAuth from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../../components/i18n';
import { SYNC_MANAGER } from '../../../utils/platformModulesHelper';
import IngestionMenu from './IngestionMenu';

const LOCAL_STORAGE_KEY = 'sync-view';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const Sync = () => {
  const theme = useTheme();
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
      width: '15%',
      isSortable: true,
    },
    uri: {
      label: 'URL',
      width: '20%',
      isSortable: true,
    },
    stream_id: {
      label: 'Stream ID',
      width: '20%',
      isSortable: true,
    },
    running: {
      label: 'Running',
      width: '20%',
      isSortable: false,
    },
    current_state: {
      label: 'Current state',
      isSortable: false,
    },
  };
  if (!platformModuleHelpers.isSyncManagerEnable()) {
    return (
      <Alert severity="info">
        {t(platformModuleHelpers.generateDisableMessage(SYNC_MANAGER))}
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
        message={
          <>
            {t(
              'You can configure your platform to consume remote OCTI streams. A list of public and commercial native feeds is available in the',
            )}{' '}
            <a
              href="https://filigran.notion.site/63392969969c4941905520d37dc7ad4a?v=0a5716cac77b4406825ba3db0acfaeb2"
              target="_blank"
              style={{ color: theme.palette.secondary.main }}
            >
              OpenCTI ecosystem space
            </a>
            .
          </>
        }
      >
        <QueryRenderer
          query={SyncLinesQuery}
          variables={{ count: 200, ...paginationOptions }}
          render={({ props }) => (
            <SyncLines
              data={props}
              paginationOptions={paginationOptions}
              refetchPaginationOptions={{ count: 200, ...paginationOptions }}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
      <SyncCreation paginationOptions={paginationOptions} />
    </div>
  );
};

export default Sync;
