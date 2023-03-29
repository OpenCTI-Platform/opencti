import React from 'react';
import Alert from '@mui/material/Alert';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import SyncLines, { SyncLinesQuery } from './sync/SyncLines';
import SyncCreation from './sync/SyncCreation';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useAuth from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../../components/i18n';
import { SYNC_MANAGER } from '../../../utils/platformModulesHelper';

const LOCAL_STORAGE_KEY = 'sync-view';

const Sync = () => {
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
    <>
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
    </>
  );
};

export default Sync;
