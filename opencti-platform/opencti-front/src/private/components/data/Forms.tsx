import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import IngestionMenu from '@components/data/IngestionMenu';
import { FormLinesPaginationQuery, FormLinesPaginationQuery$variables } from '@components/data/forms/__generated__/FormLinesPaginationQuery.graphql';
import FormLines, { formLinesQuery } from '@components/data/forms/FormLines';
import FormCreationContainer from '@components/data/forms/FormCreationContainer';
import { FormLineDummy } from '@components/data/forms/FormLine';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListLines from '../../../components/list_lines/ListLines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Security from '../../../utils/Security';
import useGranted, { INGESTION_SETINGESTIONS, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const LOCAL_STORAGE_KEY = 'forms';

const Forms = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Form intakes | Ingestion | Data'));
  const { platformModuleHelpers } = useAuth();
  const hasIngestionCapability = useGranted([INGESTION_SETINGESTIONS]);
  const hasKnowledgeUpdateCapability = useGranted([KNOWLEDGE_KNUPDATE]);

  const {
    viewStorage,
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage<FormLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      sortBy: 'name',
      orderAsc: false,
      searchTerm: '',
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
  );

  const renderLines = () => {
    const { searchTerm, sortBy, orderAsc, numberOfElements } = viewStorage;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '20%',
        isSortable: true,
      },
      description: {
        label: 'Description',
        width: '30%',
        isSortable: true,
      },
      mainEntityType: {
        label: 'Main Entity Type',
        width: '15%',
        isSortable: false,
      },
      active: {
        label: 'Status',
        width: '10%',
        isSortable: true,
      },
      updated_at: {
        label: 'Updated',
        width: '15%',
        isSortable: true,
      },
    };
    const queryRef = useQueryLoading<FormLinesPaginationQuery>(
      formLinesQuery,
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
        createButton={
          <Security needs={[INGESTION_SETINGESTIONS]}>
            <FormCreationContainer
              paginationOptions={paginationOptions}
              triggerButton={true}
            />
          </Security>
          }
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <FormLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <FormLines
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
          {t_i18n('Ingestion manager is disabled or not configured, please go to the platform settings to enable it.')}
        </Alert>
      </div>
    );
  }

  // Check if user has permission to view forms
  if (!hasIngestionCapability && !hasKnowledgeUpdateCapability) {
    return (
      <div className={classes.container}>
        <Breadcrumbs elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Ingestion') },
          { label: t_i18n('Form intakes'), current: true },
        ]}
        />
        <Alert severity="error">
          {t_i18n('You do not have permission to view form intakes.')}
        </Alert>
      </div>
    );
  }

  return (
    <div className={classes.container}>
      <IngestionMenu />
      <Breadcrumbs elements={[
        { label: t_i18n('Data') },
        { label: t_i18n('Ingestion') },
        { label: t_i18n('Form intakes'), current: true },
      ]}
      />
      {renderLines()}
    </div>
  );
};

export default Forms;
