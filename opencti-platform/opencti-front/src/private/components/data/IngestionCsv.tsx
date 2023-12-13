import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import React from 'react';
import IngestionMenu from '@components/data/IngestionMenu';
import IngestionCsvLines, { ingestionCsvLinesQuery } from '@components/data/ingestionCsv/IngestionCsvLines';
import { IngestionCsvLinesPaginationQuery, IngestionCsvLinesPaginationQuery$variables } from '@components/data/ingestionCsv/__generated__/IngestionCsvLinesPaginationQuery.graphql';
import { IngestionCsvLineDummy } from '@components/data/ingestionCsv/IngestionCsvLine';
import IngestionCsvCreation from '@components/data/ingestionCsv/IngestionCsvCreation';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { INGESTION_MANAGER } from '../../../utils/platformModulesHelper';
import ListLines from '../../../components/list_lines/ListLines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';

const LOCAL_STORAGE_KEY = 'ingestionCsvs';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const IngestionCsv = () => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { platformModuleHelpers } = useAuth();
  const {
    viewStorage,
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage<IngestionCsvLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, {
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
        width: '30%',
        isSortable: true,
      },
      ingestion_running: {
        label: 'Running',
        width: '20%',
        isSortable: false,
      },
      current_state_date: {
        label: 'Current state',
        isSortable: false,
        width: '15%',
      },
    };
    const queryRef = useQueryLoading<IngestionCsvLinesPaginationQuery>(
      ingestionCsvLinesQuery,
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
                    <IngestionCsvLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <IngestionCsvLines
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
      <Alert severity="info">
        {t(platformModuleHelpers.generateDisableMessage(INGESTION_MANAGER))}
      </Alert>
    );
  }
  return (
    <div className={classes.container}>
      <IngestionMenu/>
      <>
        {renderLines()}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IngestionCsvCreation paginationOptions={paginationOptions} />
        </Security>
      </>
    </div>
  );
};

export default IngestionCsv;
