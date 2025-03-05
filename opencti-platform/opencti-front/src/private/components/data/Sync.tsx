import React from 'react';
import Alert from '@mui/material/Alert';
import { useTheme } from '@mui/styles';
import { Theme } from 'src/components/Theme';
import { SyncLinesPaginationQuery$data, SyncLinesPaginationQuery$variables } from '@components/data/sync/__generated__/SyncLinesPaginationQuery.graphql';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import SyncLines, { SyncLinesQuery } from './sync/SyncLines';
import SyncCreation from './sync/SyncCreation';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useAuth from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../../components/i18n';
import { SYNC_MANAGER } from '../../../utils/platformModulesHelper';
import IngestionMenu from './IngestionMenu';
import AlertInfo from '../../../components/AlertInfo';
import Breadcrumbs from '../../../components/Breadcrumbs';
import Security from '../../../utils/Security';
import { INGESTION_SETINGESTIONS } from '../../../utils/hooks/useGranted';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../components/PageContainer';

const LOCAL_STORAGE_KEY = 'sync';

const Sync = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const { platformModuleHelpers } = useAuth();

  setTitle(t_i18n('Remote OCTI Streams | Ingestion | Data'));

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<SyncLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, {
    sortBy: 'name',
    orderAsc: false,
    searchTerm: '',
  });

  const dataColumns = {
    name: {
      label: 'Name',
      width: '25%',
      isSortable: true,
    },
    uri: {
      label: 'URL',
      width: '30%',
      isSortable: true,
    },
    messages: {
      label: 'Messages',
      width: '10%',
      isSortable: false,
    },
    running: {
      label: 'Status',
      width: '15%',
      isSortable: false,
    },
    current_state_date: {
      label: 'Current state',
      width: '20%',
      isSortable: true,
    },
  };

  const variables = {
    ...paginationOptions,
    count: 200,
  } as unknown as SyncLinesPaginationQuery$variables;

  if (!platformModuleHelpers.isSyncManagerEnable()) {
    return (
      <div style={{
        margin: 0,
        padding: '0 200px 50px 0',
      }}
      >
        <Alert severity="info">
          {t_i18n(platformModuleHelpers.generateDisableMessage(SYNC_MANAGER))}
        </Alert>
        <IngestionMenu />
      </div>
    );
  }

  return (
    <>
      <IngestionMenu />
      <PageContainer withRightMenu>
        <Breadcrumbs
          elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('OpenCTI Streams'), current: true }]}
        />
        <AlertInfo content={
          <>
            {t_i18n('You can configure your platform to consume OpenCTI Streams. A list of public and commercial native feeds is available in the')}{' '}
            <a
              href="https://filigran.notion.site/63392969969c4941905520d37dc7ad4a?v=0a5716cac77b4406825ba3db0acfaeb2"
              target="_blank"
              style={{ color: theme.palette.secondary.main }}
              rel="noreferrer"
            >
              {t_i18n('OpenCTI ecosystem space')}
            </a>
            .
          </>
        }
          style={{ marginBottom: theme.spacing(2) }}
        />
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
            variables={variables}
            render={({ props }: { props: SyncLinesPaginationQuery$data }) => (
              <SyncLines
                data={props}
                paginationOptions={paginationOptions}
                refetchPaginationOptions={variables}
                dataColumns={dataColumns}
                initialLoading={props === null}
              />
            )}
          />
        </ListLines>
        <Security needs={[INGESTION_SETINGESTIONS]}>
          <SyncCreation paginationOptions={paginationOptions} />
        </Security>
      </PageContainer>
    </>
  );
};

export default Sync;
