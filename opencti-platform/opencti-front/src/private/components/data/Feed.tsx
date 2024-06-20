import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Box from '@mui/material/Box';
import { FeedLinesPaginationQuery$data } from '@components/data/feeds/__generated__/FeedLinesPaginationQuery.graphql';
import { QueryRenderer } from '../../../relay/environment';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import ListLines from '../../../components/list_lines/ListLines';
import FeedLines, { FeedLinesQuery } from './feeds/FeedLines';
import FeedCreation from './feeds/FeedCreation';
import SharingMenu from './SharingMenu';
import { OrderMode, PaginationOptions } from '../../../components/list_lines';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import { TAXIIAPI_SETCOLLECTIONS } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';

const Feed = () => {
  const { t_i18n } = useFormatter();
  const LOCAL_STORAGE_KEY = 'feed';
  const navigate = useNavigate();
  const location = useLocation();
  const params = buildViewParamsFromUrlAndStorage(
    navigate,
    location,
    LOCAL_STORAGE_KEY,
  );
  const [feedState, setFeedState] = useState<{ orderAsc: boolean, searchTerm: string, view: string, sortBy: string }>({
    orderAsc: params.orderAsc !== false,
    searchTerm: params.searchTerm ?? '',
    view: params.view ?? 'lines',
    sortBy: params.sortBy ?? 'name',
  });

  function saveView() {
    saveViewParameters(
      navigate,
      location,
      LOCAL_STORAGE_KEY,
      feedState,
    );
  }

  function handleSearch(value: string) {
    setFeedState({ ...feedState, searchTerm: value });
  }

  function handleSort(field: string, orderAsc: boolean) {
    setFeedState({ ...feedState, sortBy: field, orderAsc });
  }

  useEffect(() => {
    saveView();
  }, [feedState]);

  function renderLines(paginationOptions: PaginationOptions) {
    const { sortBy, orderAsc } = feedState;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '15%',
        isSortable: true,
      },
      feed_types: {
        label: 'Entity types',
        width: '20%',
        isSortable: true,
      },
      rolling_time: {
        label: 'Rolling time',
        width: '10%',
        isSortable: true,
      },
      columns: {
        label: 'Columns',
        width: '20%',
      },
      filters: {
        label: 'Filters',
        width: '30%',
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={handleSort}
        handleSearch={handleSearch}
        displayImport={false}
        secondaryAction={true}
        keyword={feedState.searchTerm}
      >
        <QueryRenderer
          query={FeedLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }: { props: FeedLinesPaginationQuery$data }) => (
            <FeedLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  }

  const paginationOptions: PaginationOptions = {
    search: feedState.searchTerm,
    orderBy: feedState.sortBy ? feedState.sortBy : null,
    orderMode: feedState.orderAsc ? OrderMode.asc : OrderMode.desc,
  };
  return (
    <Box sx={{
      margin: 0,
      padding: '0 200px 50px 0',
    }}
    >
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Data') }, { label: t_i18n('Data sharing') }, { label: t_i18n('CSV feeds'), current: true }]} />
      <SharingMenu/>
      {feedState.view === 'lines' ? renderLines(paginationOptions) : ''}
      <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
        <FeedCreation paginationOptions={paginationOptions} />
      </Security>
    </Box>
  );
};

export default Feed;
