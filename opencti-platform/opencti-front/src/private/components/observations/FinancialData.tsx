import React, { FunctionComponent } from 'react';
import ExportContextProvider from 'src/utils/ExportContextProvider';
import { usePaginationLocalStorage } from 'src/utils/hooks/useLocalStorage';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from 'src/utils/filters/filtersUtils';
import ListLines from 'src/components/list_lines/ListLines';
import useEntityToggle from 'src/utils/hooks/useEntityToggle';
import useCopy from 'src/utils/hooks/useCopy';
import useAuth from 'src/utils/hooks/useAuth';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import { makeStyles } from '@mui/styles';
import { Theme } from 'src/components/Theme';
import FinancialDataLines, { financialDataLinesQuery, financialDataLinesSearchQuery } from './financial_data/FinancialDataLines';
import ToolBar from '../data/ToolBar';
import { FinancialDataLinesPaginationQuery, FinancialDataLinesPaginationQuery$variables } from './financial_data/__generated__/FinancialDataLinesPaginationQuery.graphql';
import { FinancialDataLineDummy } from './financial_data/FinancialDataLine';
import { FinancialDataLinesSearchQuery$data } from './financial_data/__generated__/FinancialDataLinesSearchQuery.graphql';
import { FinancialDataLine_node$data } from './financial_data/__generated__/FinancialDataLine_node.graphql';
import FinancialDataRightBar from './financial_data/FinancialDataRightBar';
import FinancialDataCreation from './financial_data/FinancialDataCreation';

const LOCAL_STORAGE_KEY = 'financialData';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    paddingRight: 250,
  },
}));

const FinancialData: FunctionComponent = () => {
  const classes = useStyles();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage<FinancialDataLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: emptyFilterGroup,
      searchTerm: '',
      sortBy: 'created_at',
      orderAsc: false,
      openExports: false,
      types: [] as string[],
    },
  );
  if (!paginationOptions.types || paginationOptions.types.length === 0) {
    paginationOptions.types = ['Financial-Account', 'Financial-Asset', 'Financial-Transaction'];
  }
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
    types,
  } = viewStorage;

  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<FinancialDataLine_node$data>(LOCAL_STORAGE_KEY);

  const getValuesForCopy = (
    data: FinancialDataLinesSearchQuery$data,
  ) => {
    return (data.stixCyberObservables?.edges ?? []).map((o) => (o
      ? { id: o.node.id, value: o.node.observable_value }
      : { id: '', value: '' }));
  };

  const handleCopy = useCopy<FinancialDataLinesSearchQuery$data>(
    {
      filters: {
        mode: filters?.mode ?? 'and',
        filters: (filters?.filters ?? []).concat({
          key: 'entity_type',
          values: types ?? [],
          operator: 'eq',
          mode: 'or',
        }),
        filterGroups: filters?.filterGroups ?? [],
      },
      searchTerm: searchTerm ?? '',
      query: financialDataLinesSearchQuery,
      selectedValues: Object.values(selectedElements).map(
        ({ observable_value }) => observable_value,
      ),
      deselectedIds: Object.values(deSelectedElements).map((o) => o.id),
      getValuesForCopy,
    },
    selectAll,
  );

  const buildColumns = () => {
    return {
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      observable_value: {
        label: 'Value',
        width: '25%',
        isSortable: isRuntimeSort,
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
        width: '12%',
        isSortable: false,
      },
      created_at: {
        label: 'Date',
        width: '13%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        width: '10%',
        isSortable: isRuntimeSort,
      },
    };
  };

  const queryRef = useQueryLoading<FinancialDataLinesPaginationQuery>(
    financialDataLinesQuery,
    paginationOptions,
  );

  const toolBarFilters = useBuildEntityTypeBasedFilterContext('Stix-Cyber-Observable', filters);

  const renderLines = () => (
    <ListLines
      sortBy={sortBy}
      orderAsc={orderAsc}
      dataColumns={buildColumns()}
      handleSort={helpers.handleSort}
      handleSearch={helpers.handleSearch}
      handleAddFilter={helpers.handleAddFilter}
      handleRemoveFilter={helpers.handleRemoveFilter}
      handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
      handleSwitchLocalMode={helpers.handleSwitchLocalMode}
      handleToggleSelectAll={handleToggleSelectAll}
      openExports={openExports}
      selectAll={selectAll}
      exportEntityType="Financial-Data"
      exportContext={null}
      keyword={searchTerm}
      filters={filters}
      iconExtension={true}
      paginationOptions={paginationOptions}
      numberOfElements={numberOfElements}
      availableFilterKeys={[
        'objectLabel',
        'objectMarking',
        'created_at',
        'x_opencti_score',
        'createdBy',
        'sightedBy',
        'creator_id',
      ]}
    >
      {queryRef && (
        <React.Suspense
          fallback={
            <>
              {Array(20)
                .fill(0)
                .map((_, idx) => (
                  <FinancialDataLineDummy key={idx} />
                ))
              }
            </>
          }
        >
          <FinancialDataLines
            queryRef={queryRef}
            paginationOptions={paginationOptions}
            dataColumns={buildColumns()}
            onLabelClick={helpers.handleAddFilter}
            selectedElements={selectedElements}
            deSelectedElements={deSelectedElements}
            onToggleEntity={onToggleEntity}
            selectAll={selectAll}
            setNumberOfElements={helpers.handleSetNumberOfElements}
          />
          <ToolBar
            selectedElements={selectedElements}
            deSelectedElements={deSelectedElements}
            numberOfSelectedElements={numberOfSelectedElements}
            selectAll={selectAll}
            filters={toolBarFilters}
            search={searchTerm}
            handleClearSelectedElements={handleClearSelectedElements}
            variant="large"
            handleCopy={handleCopy}
          />
        </React.Suspense>
      )}
    </ListLines>
  );

  const handleToggle = (type: string) => {
    if (types?.includes(type)) {
      helpers.handleAddProperty(
        'types',
        types.filter((x) => x !== type),
      );
    } else {
      helpers.handleAddProperty(
        'types',
        types ? [...types, type] : [type],
      );
    }
  };

  const handleClear = () => {
    helpers.handleAddProperty('types', []);
  };

  return (
    <ExportContextProvider>
      <div className={classes.container}>
        {renderLines()}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <FinancialDataCreation
            paginationKey="Pagination_stixCyberObservables"
            paginationOptions={paginationOptions}
            contextual={false}
            open={false}
            speeddial={false}
            type={''}
            display={undefined}
          />
        </Security>
        <FinancialDataRightBar
          handleToggle={handleToggle}
          handleClear={handleClear}
          types={types}
        />
      </div>
    </ExportContextProvider>
  );
};

export default FinancialData;
