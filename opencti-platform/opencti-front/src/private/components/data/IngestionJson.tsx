import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import React from 'react';
import IngestionMenu from '@components/data/IngestionMenu';
import IngestionJsonLines, { ingestionJsonLinesQuery } from '@components/data/ingestionJson/IngestionJsonLines';
import {
  IngestionJsonLinesPaginationQuery,
  IngestionJsonLinesPaginationQuery$variables,
} from '@components/data/ingestionJson/__generated__/IngestionJsonLinesPaginationQuery.graphql';
import { IngestionJsonLineDummy } from '@components/data/ingestionJson/IngestionJsonLine';
import { IngestionJsonCreationContainer } from '@components/data/ingestionJson/IngestionJsonCreation';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { INGESTION_MANAGER } from '../../../utils/platformModulesHelper';
import ListLines from '../../../components/list_lines/ListLines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { INGESTION_SETINGESTIONS } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const LOCAL_STORAGE_KEY = 'ingestionJsons';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const IngestionJson = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Json Feeds | Ingestion | Data'));
  const { platformModuleHelpers } = useAuth();
  const {
    viewStorage,
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage<IngestionJsonLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, {
    sortBy: 'name',
    orderAsc: false,
    searchTerm: '',
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  });

  const renderLines = () => {
    const { searchTerm, sortBy, orderAsc, numberOfElements } = viewStorage;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '20%',
        isSortable: true,
      },
      uri: {
        label: 'URL',
        width: '25%',
        isSortable: true,
      },
      ingestion_running: {
        label: 'Status',
        width: '15%',
        isSortable: false,
      },
      last_execution_date: {
        label: 'Last run',
        width: '15%',
        isSortable: false,
      },
      current_state_hash: {
        label: 'Current state',
        isSortable: false,
        width: '15%',
      },
    };
    const queryRef = useQueryLoading<IngestionJsonLinesPaginationQuery>(
      ingestionJsonLinesQuery,
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
        secondaryAction={true}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        keyword={searchTerm}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <IngestionJsonLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <IngestionJsonLines
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
  if (!platformModuleHelpers.isIngestionManagerEnable()) {
    return (
      <div className={classes.container}>
        <Alert severity="info">
          {t_i18n(platformModuleHelpers.generateDisableMessage(INGESTION_MANAGER))}
        </Alert>
        <IngestionMenu/>
      </div>
    );
  }

  return (
    <div className={classes.container}>
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('JSON feeds'), current: true }]} />
      <IngestionMenu/>
      {renderLines()}
      <Security needs={[INGESTION_SETINGESTIONS]}>
        <IngestionJsonCreationContainer
          open={false}
          handleClose={() => {
          }}
          paginationOptions={paginationOptions}
          isDuplicated={false}
        />
      </Security>
    </div>
  );
};

export default IngestionJson;
