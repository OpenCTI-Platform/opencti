import React, { FunctionComponent } from 'react';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import ObservedDatasLines, {
  observedDatasLinesQuery,
} from './observed_data/ObservedDatasLines';
import ObservedDataCreation from './observed_data/ObservedDataCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { ObservedDataLine_node$data } from './observed_data/__generated__/ObservedDataLine_node.graphql';
import {
  ObservedDatasLinesPaginationQuery$data,
  ObservedDatasLinesPaginationQuery$variables,
} from './observed_data/__generated__/ObservedDatasLinesPaginationQuery.graphql';
import { ModuleHelper } from '../../../utils/platformModulesHelper';

const LOCAL_STORAGE_KEY = 'view-observedDatas';

interface ObservedDatasProps {
  objectId: string;
  authorId: string;
  onChangeOpenExports: () => void;
}

const ObservedDatas: FunctionComponent<ObservedDatasProps> = ({
  objectId,
  authorId,
  onChangeOpenExports,
}) => {
  const additionnalFilters = [];
  if (authorId) {
    additionnalFilters.push({
      key: 'createdBy',
      values: [authorId],
      operator: 'eq',
      filterMode: 'or',
    });
  }
  if (objectId) {
    additionnalFilters.push({
      key: 'objectContains',
      values: [objectId],
      operator: 'eq',
      filterMode: 'or',
    });
  }
  const {
    viewStorage,
    helpers: storageHelpers,
    paginationOptions,
  } = usePaginationLocalStorage<ObservedDatasLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'last_observed',
      orderAsc: false,
      openExports: false,
      filters: {},
    },
    additionnalFilters,
  );
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
  } = viewStorage;
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<ObservedDataLine_node$data>(LOCAL_STORAGE_KEY);
  const renderLines = (helper: ModuleHelper | undefined) => {
    let exportContext = null;
    if (objectId) {
      exportContext = `of-entity-${objectId}`;
    } else if (authorId) {
      exportContext = `of-entity-${authorId}`;
    }
    let toolBarFilters = filters;
    toolBarFilters = {
      ...toolBarFilters,
      entity_type: [{ id: 'Observed-Data', value: 'Observed-Data' }],
    };
    const isRuntimeSort = helper?.isRuntimeFieldEnable();
    const dataColumns = {
      name: {
        label: 'Name',
        width: '25%',
        isSortable: false,
      },
      number_observed: {
        label: 'Nb.',
        width: 80,
        isSortable: true,
      },
      first_observed: {
        label: 'First obs.',
        width: '12%',
        isSortable: true,
      },
      last_observed: {
        label: 'Last obs.',
        width: '12%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '15%',
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '15%',
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
      },
    };
    return (
      <>
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={storageHelpers.handleSearch}
          handleAddFilter={storageHelpers.handleAddFilter}
          handleRemoveFilter={storageHelpers.handleRemoveFilter}
          handleToggleExports={storageHelpers.handleToggleExports}
          openExports={openExports}
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          noPadding={typeof onChangeOpenExports === 'function'}
          exportEntityType="Observed-Data"
          exportContext={exportContext}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          iconExtension={true}
          availableFilterKeys={[
            'x_opencti_workflow_id',
            'labelledBy',
            'markedBy',
            'createdBy',
            'source_reliability',
            'confidence',
            'created_start_date',
            'created_end_date',
          ]}
        >
          <QueryRenderer
            query={observedDatasLinesQuery}
            variables={{ ...paginationOptions }}
            render={({
              props,
            }: {
              props: ObservedDatasLinesPaginationQuery$data;
            }) => (
              <ObservedDatasLines
                data={props}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
                onLabelClick={storageHelpers.handleAddFilter}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
              />
            )}
          />
        </ListLines>
        <ToolBar
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          numberOfSelectedElements={numberOfSelectedElements}
          selectAll={selectAll}
          search={searchTerm}
          filters={toolBarFilters}
          handleClearSelectedElements={handleClearSelectedElements}
          type="Observed-Data"
        />
      </>
    );
  };

  return (
    <UserContext.Consumer>
      {({ platformModuleHelpers }) => (
        <ExportContextProvider>
          <div>
            {renderLines(platformModuleHelpers)}
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <ObservedDataCreation paginationOptions={paginationOptions} />
            </Security>
          </div>
        </ExportContextProvider>
      )}
    </UserContext.Consumer>
  );
};

export default ObservedDatas;
