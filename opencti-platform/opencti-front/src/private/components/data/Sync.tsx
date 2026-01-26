import React, { useContext } from 'react';
import MuiAlert from '@mui/material/Alert';
import { SyncLinesPaginationQuery$data, SyncLinesPaginationQuery$variables } from '@components/data/sync/__generated__/SyncLinesPaginationQuery.graphql';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import SyncLines, { SyncLinesQuery } from './sync/SyncLines';
import SyncCreation from './sync/SyncCreation';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useAuth, { UserContext } from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../../components/i18n';
import { SYNC_MANAGER } from '../../../utils/platformModulesHelper';
import IngestionMenu from './IngestionMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';
import Security from '../../../utils/Security';
import { INGESTION_SETINGESTIONS } from '../../../utils/hooks/useGranted';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../components/PageContainer';
import SyncImport from '@components/data/SyncImport';
import { isNotEmptyField } from '../../../utils/utils';
import GradientButton from '../../../components/GradientButton';
import { PaginationOptions } from '../../../components/list_lines';

const LOCAL_STORAGE_KEY = 'sync';

const Sync = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const { platformModuleHelpers } = useAuth();
  const { settings, isXTMHubAccessible } = useContext(UserContext);

  const importFromHubUrl = isNotEmptyField(settings?.platform_xtmhub_url)
    ? `${settings.platform_xtmhub_url}/redirect/opencti_integrations?platform_id=${settings.id}`
    : '';

  setTitle(t_i18n('Remote OCTI Streams | Ingestion | Data'));

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<PaginationOptions>(LOCAL_STORAGE_KEY, {
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
        <MuiAlert severity="info">
          {t_i18n(platformModuleHelpers.generateDisableMessage(SYNC_MANAGER))}
        </MuiAlert>
        <IngestionMenu />
      </div>
    );
  }

  return (
    <div data-testid="streams-page">
      <IngestionMenu />
      <PageContainer withRightMenu>
        <Breadcrumbs
          elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('OpenCTI Streams'), current: true }]}
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
          createButton={(
            <Security needs={[INGESTION_SETINGESTIONS]}>
              <>
                <SyncImport paginationOptions={paginationOptions} />
                {isXTMHubAccessible && isNotEmptyField(importFromHubUrl) && (
                  <GradientButton
                    size="small"
                    sx={{ marginLeft: 1 }}
                    href={importFromHubUrl}
                    target="_blank"
                    title={t_i18n('Import from Hub')}
                  >
                    {t_i18n('Import from Hub')}
                  </GradientButton>
                )}
                <SyncCreation triggerButton paginationOptions={paginationOptions} />
              </>
            </Security>
          )}
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
      </PageContainer>
    </div>
  );
};

export default Sync;
