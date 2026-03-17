import React, { useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Stream as StreamIcon } from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import SharingMenu from './SharingMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { graphql } from 'react-relay';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../components/Theme';
import Security from '../../../utils/Security';
import { TAXIIAPI, TAXIIAPI_SETCOLLECTIONS } from '../../../utils/hooks/useGranted';
import StreamPopover from '@components/data/stream/StreamPopover';
import stopEvent from '../../../utils/domEvent';
import ItemCopy from '../../../components/ItemCopy';
import { StreamLine_node$data } from '@components/data/__generated__/StreamLine_node.graphql';
import ItemBoolean from '../../../components/ItemBoolean';
import { EMPTY_VALUE } from '../../../utils/String';
import Tag from '@common/tag/Tag';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty } from '../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../components/FilterIconButton';
import StreamConsumersDrawer from '@components/data/stream/StreamConsumersDrawer';
import StreamCollectionCreation from '@components/data/stream/StreamCollectionCreation';
import { StreamLinesPaginationQuery, StreamLinesPaginationQuery$variables } from '@components/data/__generated__/StreamLinesPaginationQuery.graphql';
import { StreamLines_data$data } from '@components/data/__generated__/StreamLines_data.graphql';

const LOCAL_STORAGE_KEY = 'stream';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const streamLineFragment = graphql`
    fragment StreamLine_node on StreamCollection {
      id
      name
      description
      filters
      stream_public
      stream_live
      consumers {
        connectionId
        estimatedOutOfDepth
      }
      ...StreamCollectionEdition_streamCollection
    }
  `;

const streamLinesFragment = graphql`
  fragment StreamLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StreamCollectionOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  )
  @refetchable(queryName: "StreamLinesRefetchQuery") {
    streamCollections(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_streamCollections") {
      edges {
        node {
          ...StreamLine_node
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

export const streamLinesPaginationQuery = graphql`
  query StreamLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StreamCollectionOrdering
    $orderMode: OrderingMode
  ) {
    ...StreamLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

const Stream = () => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Live Streams | Data Sharing | Data'));
  const [streamConsumer, setStreamConsumer] = useState<StreamLine_node$data | undefined>();
  const [openStreamConsumerDrawer, setOpenStreamConsumerDrawer] = useState<boolean>(false);
  const handelOpenStreamConsumerDrawer = () => setOpenStreamConsumerDrawer(true);
  const handelCloseStreamConsumerDrawer = () => setOpenStreamConsumerDrawer(false);

  const initialValues = {
    sortBy: 'name',
    orderAsc: false,
    openExports: false,
    searchTerm: '',
  };
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<StreamLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: viewStorage.filters,
  } as unknown as StreamLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<StreamLinesPaginationQuery>(
    streamLinesPaginationQuery,
    queryPaginationOptions,
  );

  const computeConsumersHealth = (consumers: StreamLine_node$data['consumers']) => {
    if (!consumers || consumers.length === 0) {
      return { count: 0, label: t_i18n('No consumers'), hexColor: null };
    }
    const ONE_HOUR = 3600;
    const ONE_DAY = 86400;
    const hasCritical = consumers.some((c) => !!c.estimatedOutOfDepth && c.estimatedOutOfDepth > 0 && c.estimatedOutOfDepth < ONE_HOUR);
    const hasWarning = consumers.some((c) => !!c.estimatedOutOfDepth && c.estimatedOutOfDepth >= ONE_HOUR && c.estimatedOutOfDepth < ONE_DAY);
    if (hasCritical) {
      return { count: consumers.length, label: `${consumers.length} - ${t_i18n('At risk')}`, hexColor: '#c62828' };
    }
    if (hasWarning) {
      return { count: consumers.length, label: `${consumers.length} - ${t_i18n('Degraded')}`, hexColor: '#d84315' };
    }
    return { count: consumers.length, label: `${consumers.length} - ${t_i18n('Healthy')}`, hexColor: '#2e7d32' };
  };

  const dataColumns = {
    name: {
      label: 'Name',
      percentWidth: 10,
      isSortable: true,
    },
    description: {
      label: 'Description',
      percentWidth: 20,
      isSortable: false,
    },
    id: {
      label: 'Stream ID',
      percentWidth: 25,
      isSortable: true,
      render: ({ id }: StreamLine_node$data) => (
        <ItemCopy content={id} variant="inLine" />
      ),
    },
    stream_public: {
      id: 'stream_public',
      label: 'Public',
      percentWidth: 10,
      isSortable: true,
      render: ({ stream_public }: StreamLine_node$data) => (
        <ItemBoolean
          label={stream_public ? t_i18n('Yes') : t_i18n('No')}
          status={stream_public}
        />
      ),
    },
    stream_live: {
      id: 'stream_live',
      label: 'Status',
      percentWidth: 10,
      isSortable: true,
      render: ({ stream_live }: StreamLine_node$data) => (
        <ItemBoolean
          label={stream_live ? t_i18n('Started') : t_i18n('Stopped')}
          status={stream_live}
        />
      ),
    },
    consumers: {
      id: 'consumers',
      label: 'Consumers',
      percentWidth: 10,
      isSortable: false,
      render: ({ consumers }: StreamLine_node$data) => {
        const health = computeConsumersHealth(consumers);
        return health.count === 0
          ? <>{EMPTY_VALUE}</>
          : (
              <Tag
                label={health.label}
                color={health.hexColor}
              />
            );
      },
    },
    filters: {
      id: 'filters',
      label: 'Filters',
      percentWidth: 15,
      isSortable: false,
      render: ({ filters }: StreamLine_node$data) => {
        const deserializedFilters = deserializeFilterGroupForFrontend(filters);
        return isFilterGroupNotEmpty(deserializedFilters)
          ? (
              <FilterIconButton
                filters={deserializedFilters}
                dataColumns={dataColumns}
                variant="small"
                entityTypes={['Stix-Filtering']}
              />
            )
          : EMPTY_VALUE;
      },
    },
  };

  const preloadedPaginationOptions = {
    linesQuery: streamLinesPaginationQuery,
    linesFragment: streamLinesFragment,
    queryRef,
    nodePath: ['streamCollections', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StreamLinesPaginationQuery>;

  return (
    <div className={classes.container} data-testid="sharing-streams-page">
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Data sharing') }, { label: t_i18n('Live streams'), current: true }]} />
      <SharingMenu />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: StreamLines_data$data) => data.streamCollections?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={viewStorage.filters}
          lineFragment={streamLineFragment}
          preloadedPaginationProps={preloadedPaginationOptions}
          disableLineSelection
          icon={() => (
            <StreamIcon sx={{
              color: theme.palette.primary.main,
            }}
            />
          )}
          actions={(node) => (
            <div onClick={(event) => stopEvent(event)}>
              <Security needs={[TAXIIAPI]}>
                <StreamPopover
                  streamCollection={node}
                  paginationOptions={paginationOptions}
                />
              </Security>
            </div>
          )}
          onLineClick={(node) => {
            setStreamConsumer(node);
            handelOpenStreamConsumerDrawer();
          }}
          createButton={(
            <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
              <StreamCollectionCreation paginationOptions={paginationOptions} />
            </Security>
          )}
        />
      )}
      <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
        <StreamConsumersDrawer
          streamCollectionId={streamConsumer?.id}
          streamCollectionName={streamConsumer?.name}
          open={openStreamConsumerDrawer}
          onClose={() => {
            setStreamConsumer(undefined);
            handelCloseStreamConsumerDrawer();
          }}
        />
      </Security>
    </div>
  );
};

export default Stream;
