import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import ListLines from '../../../components/list_lines/ListLines';
import GroupingsLines, { groupingsLinesQuery } from './groupings/GroupingsLines';
import GroupingCreation from './groupings/GroupingCreation';
import ToolBar from '../data/ToolBar';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { GroupingsLinesPaginationQuery, GroupingsLinesPaginationQuery$variables } from './groupings/__generated__/GroupingsLinesPaginationQuery.graphql';
import { GroupingLine_node$data } from './groupings/__generated__/GroupingLine_node.graphql';
import { GroupingLineDummy } from './groupings/GroupingLine';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useDynamicHeader from '../../../utils/hooks/useDynamicHeader';

const LOCAL_STORAGE_KEY = 'groupings';

interface GroupingsProps {
  match: { params: { groupingContext: string } };
}

const Groupings: FunctionComponent<GroupingsProps> = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useDynamicHeader();
  setTitle(t_i18n('OpenCTI - Analyses: Groupings'));
  const { isFeatureEnable } = useHelper();
  const FAB_REPLACED = isFeatureEnable('FAB_REPLACEMENT');
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<GroupingsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: { number: 0, symbol: '', original: 0 },
      filters: {
        ...emptyFilterGroup,
        filters: useGetDefaultFilterObject(['context'], ['Grouping']),
      },
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
      count: 25,
    },
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
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle<GroupingLine_node$data>(LOCAL_STORAGE_KEY);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Grouping', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as GroupingsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<GroupingsLinesPaginationQuery>(
    groupingsLinesQuery,
    queryPaginationOptions,
  );

  const renderLines = () => {
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = (numberOfElements?.original ?? 0)
        - Object.keys(deSelectedElements || {}).length;
    }
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '25%',
        isSortable: true,
      },
      context: {
        label: 'Context',
        width: '8%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      creator: {
        label: 'Creators',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '15%',
        isSortable: false,
      },
      created: {
        label: 'Original creation date',
        width: '10%',
        isSortable: true,
      },
      x_opencti_workflow_id: {
        label: 'Status',
        width: '8%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
        width: '8%',
      },
    };
    return (
      <div data-testid="groupings-page">
        <ListLines
          helpers={storageHelpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={storageHelpers.handleSearch}
          handleAddFilter={storageHelpers.handleAddFilter}
          handleRemoveFilter={storageHelpers.handleRemoveFilter}
          handleToggleExports={storageHelpers.handleToggleExports}
          handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
          handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
          openExports={openExports}
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          exportContext={{ entity_type: 'Grouping' }}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={queryPaginationOptions}
          numberOfElements={numberOfElements}
          iconExtension={true}
          createButton={FAB_REPLACED && <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <GroupingCreation paginationOptions={queryPaginationOptions} />
          </Security>}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <GroupingLineDummy key={idx} dataColumns={dataColumns}/>
                    ))}
                </>
              }
            >
              <GroupingsLines
                queryRef={queryRef}
                paginationOptions={queryPaginationOptions}
                dataColumns={dataColumns}
                onLabelClick={storageHelpers.handleAddFilter}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
              />
            </React.Suspense>
          )}
        </ListLines>
        <ToolBar
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          numberOfSelectedElements={numberOfSelectedElements}
          selectAll={selectAll}
          search={searchTerm}
          filters={contextFilters}
          handleClearSelectedElements={handleClearSelectedElements}
          type="Grouping"
        />
      </div>
    );
  };
  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Groupings'), current: true }]} />
      {renderLines()}
      {!FAB_REPLACED
        && <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <GroupingCreation paginationOptions={queryPaginationOptions} />
        </Security>
      }
    </ExportContextProvider>
  );
};

export default Groupings;
