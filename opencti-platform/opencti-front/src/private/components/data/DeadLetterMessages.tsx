import React, { useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../components/i18n';
import IngestionMenu from './IngestionMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../relay/environment';
import { RelayError } from '../../../relay/relayTypes';
import Button from '../../../components/common/button/Button';
import DeadLetterMessagePopover from './deadLetterMessage/DeadLetterMessagePopover';
import stopEvent from '../../../utils/domEvent';
import { DeadLetterMessagesLinesPaginationQuery, DeadLetterMessagesLinesPaginationQuery$variables } from './__generated__/DeadLetterMessagesLinesPaginationQuery.graphql';
import { DeadLetterMessagesLines_data$data } from './__generated__/DeadLetterMessagesLines_data.graphql';
import { DeadLetterMessagesLine_node$data } from './__generated__/DeadLetterMessagesLine_node.graphql';
import { DeadLetterMessagesCountQuery } from './__generated__/DeadLetterMessagesCountQuery.graphql';
import { DeadLetterMessagesImportMutation } from './__generated__/DeadLetterMessagesImportMutation.graphql';

const LOCAL_STORAGE_KEY = 'deadLetterMessages';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const deadLetterMessageLineFragment = graphql`
  fragment DeadLetterMessagesLine_node on DeadLetterMessage {
    id
    original_connector_id
  }
`;

const deadLetterMessagesLinesFragment = graphql`
  fragment DeadLetterMessagesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DeadLetterMessagesOrdering", defaultValue: original_connector_id }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "DeadLetterMessagesLinesRefetchQuery") {
    deadLetterMessages(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_deadLetterMessages") {
      edges {
        node {
          id
          ...DeadLetterMessagesLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

export const deadLetterMessagesLinesPaginationQuery = graphql`
  query DeadLetterMessagesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: DeadLetterMessagesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...DeadLetterMessagesLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const deadLetterMessagesCountQuery = graphql`
  query DeadLetterMessagesCountQuery {
    deadLetterQueueMessageCount
  }
`;

const deadLetterMessagesImportMutation = graphql`
  mutation DeadLetterMessagesImportMutation {
    importDeadLetterMessages
  }
`;

const DeadLetterQueueHeader: React.FC = () => {
  const { t_i18n } = useFormatter();
  const [fetchKey, setFetchKey] = useState(0);
  const [importing, setImporting] = useState(false);

  const data = useLazyLoadQuery<DeadLetterMessagesCountQuery>(
    deadLetterMessagesCountQuery,
    {},
    {
      fetchPolicy: 'store-and-network',
      fetchKey,
    },
  );

  const messageCount = data?.deadLetterQueueMessageCount ?? 0;

  const [commitImport] = useApiMutation<DeadLetterMessagesImportMutation>(
    deadLetterMessagesImportMutation,
  );

  const handleImport = () => {
    setImporting(true);
    commitImport({
      variables: {},
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Dead letter messages imported successfully'));
        setImporting(false);
        setFetchKey((prev) => prev + 1);
      },
      onError: (error) => {
        const { errors } = (error as unknown as RelayError).res;
        MESSAGING$.notifyError(errors.at(0)?.message);
        setImporting(false);
      },
      updater: (store) => {
        store.invalidateStore();
      },
    });
  };

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
      <Typography variant="body1">
        {t_i18n('Messages in dead letter queue')}: <strong>{messageCount}</strong>
      </Typography>
      <Button
        onClick={handleImport}
        disabled={messageCount < 1 || importing}
      >
        {importing ? t_i18n('Importing...') : t_i18n('Import messages')}
      </Button>
    </Box>
  );
};

const DeadLetterMessages = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Dead letter | Ingestion | Data'));

  const initialValues = {
    sortBy: 'original_connector_id',
    orderAsc: false,
    searchTerm: '',
  };

  const {
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<DeadLetterMessagesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const queryRef = useQueryLoading<DeadLetterMessagesLinesPaginationQuery>(
    deadLetterMessagesLinesPaginationQuery,
    paginationOptions,
  );

  const dataColumns = {
    original_connector_id: {
      label: 'Connector ID',
      percentWidth: 40,
      isSortable: false,
    },
  };

  const preloadedPaginationOptions = {
    linesQuery: deadLetterMessagesLinesPaginationQuery,
    linesFragment: deadLetterMessagesLinesFragment,
    queryRef,
    nodePath: ['deadLetterMessages', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DeadLetterMessagesLinesPaginationQuery>;

  return (
    <div className={classes.container} data-testid="dead-letter-messages-page">
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Ingestion') },
          { label: t_i18n('Dead letter'), current: true },
        ]}
      />
      <IngestionMenu />
      <React.Suspense fallback={<div />}>
        <DeadLetterQueueHeader />
      </React.Suspense>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: DeadLetterMessagesLines_data$data) => data.deadLetterMessages?.edges?.map((n: { node: DeadLetterMessagesLine_node$data } | null) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          lineFragment={deadLetterMessageLineFragment}
          preloadedPaginationProps={preloadedPaginationOptions}
          disableNavigation
          disableLineSelection
          actions={(row: DeadLetterMessagesLine_node$data) => (
            <div onClick={(event) => stopEvent(event)}>
              <DeadLetterMessagePopover
                messageId={row.id}
                paginationOptions={paginationOptions}
              />
            </div>
          )}
        />
      )}
    </div>
  );
};

export default DeadLetterMessages;
