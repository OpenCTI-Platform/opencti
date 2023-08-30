import React from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import ToolsLines, { toolsLinesQuery } from './tools/ToolsLines';
import ToolCreation from './tools/ToolCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { ToolLineDummy } from './tools/ToolLine';
import {
  ToolsLinesPaginationQuery,
  ToolsLinesPaginationQuery$variables,
} from './tools/__generated__/ToolsLinesPaginationQuery.graphql';
import { initialFilterGroup } from '../../../utils/filters/filtersUtils';

const LOCAL_STORAGE_KEY = 'view-tools';

const Tools = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ToolsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: initialFilterGroup,
    },
  );

  const renderLines = () => {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = viewStorage;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '35%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '25%',
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
    const queryRef = useQueryLoading<ToolsLinesPaginationQuery>(
      toolsLinesQuery,
      paginationOptions,
    );
    return (
      <ListLines
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
        exportEntityType="Tool"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'x_opencti_workflow_id',
          'objectLabel',
          'objectMarking',
          'createdBy',
          'source_reliability',
          'confidence',
          'created',
        ]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((idx) => (
                    <ToolLineDummy
                      key={idx}
                      dataColumns={dataColumns}
                    />
                  ))}
              </>
            }
          >
            <ToolsLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
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
          <ToolCreation paginationOptions={paginationOptions} />
        </Security>
      </>
  );
};

export default Tools;
