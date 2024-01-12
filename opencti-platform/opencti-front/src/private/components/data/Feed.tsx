import React, { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom-v5-compat';
import Box from '@mui/material/Box';
import { FeedLinesPaginationQuery$data } from '@components/data/feeds/__generated__/FeedLinesPaginationQuery.graphql';
import { useHistory } from 'react-router-dom';
import { QueryRenderer } from '../../../relay/environment';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import ListLines from '../../../components/list_lines/ListLines';
import FeedLines, { FeedLinesQuery } from './feeds/FeedLines';
import FeedCreation from './feeds/FeedCreation';
import SharingMenu from './SharingMenu';
import { OrderMode, PaginationOptions } from '../../../components/list_lines';

const Feed = () => {
  const LOCAL_STORAGE_KEY = 'feed';
  const history = useHistory();
  const location = useLocation();
  const params = buildViewParamsFromUrlAndStorage(
    history,
    location,
    LOCAL_STORAGE_KEY,
  );
  const [feedState, setFeedState] = useState<{ orderAsc: boolean, searchTerm: string, view: string, sortBy: string }>({
    orderAsc: params.orderAsc !== false,
    searchTerm: params.searchTerm ?? '',
    view: params.view ?? 'lines',
    sortBy: params.sortBy,
  });

  function saveView() {
    saveViewParameters(
      history,
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
      <SharingMenu/>
      {feedState.view === 'lines' ? renderLines(paginationOptions) : ''}
      <FeedCreation paginationOptions={paginationOptions}/>
    </Box>
  );
};

export default Feed;
