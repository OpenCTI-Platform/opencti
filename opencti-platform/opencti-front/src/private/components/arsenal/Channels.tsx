import React from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import ChannelsLines, { channelsLinesQuery } from './channels/ChannelsLines';
import ChannelCreation from './channels/ChannelCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { ChannelLineDummy } from './channels/ChannelLine';
import { ChannelsLinesPaginationQuery, ChannelsLinesPaginationQuery$variables } from './channels/__generated__/ChannelsLinesPaginationQuery.graphql';
import { buildEntityTypeBasedFilterContext, emptyFilterGroup, getDefaultFilterObjFromArray } from '../../../utils/filters/filtersUtils';

const LOCAL_STORAGE_KEY = 'channels';

const Channels = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ChannelsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: {
        ...emptyFilterGroup,
        filters: getDefaultFilterObjFromArray(['channel_types']),
      },
    },
  );

  const {
    sortBy,
    orderAsc,
    searchTerm,
    filters,
    openExports,
    numberOfElements,
  } = viewStorage;

  const contextFilters = buildEntityTypeBasedFilterContext('Channel', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ChannelsLinesPaginationQuery$variables;

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '30%',
        isSortable: true,
      },
      channel_types: {
        label: 'Types',
        width: '15%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '20%',
        isSortable: false,
      },
      created: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        width: '15%',
        isSortable: true,
      },
    };
    const queryRef = useQueryLoading<ChannelsLinesPaginationQuery>(
      channelsLinesQuery,
      queryPaginationOptions,
    );
    return (
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        handleToggleExports={helpers.handleToggleExports}
        openExports={openExports}
        exportContext={{ entity_type: 'Channel' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={queryPaginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'channel_types',
          'workflow_id',
          'objectLabel',
          'objectMarking',
          'createdBy',
          'source_reliability',
          'confidence',
          'created',
          'name',
        ]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <ChannelLineDummy
                      key={idx}
                      dataColumns={dataColumns}
                    />
                  ))}
              </>
            }
          >
            <ChannelsLines
              queryRef={queryRef}
              paginationOptions={queryPaginationOptions}
              dataColumns={dataColumns}
              onLabelClick={helpers.handleAddFilter}
              setNumberOfElements={helpers.handleSetNumberOfElements}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };

  return (
    <>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ChannelCreation paginationOptions={queryPaginationOptions} />
      </Security>
    </>
  );
};
export default Channels;
