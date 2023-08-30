import { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { React } from 'mdi-material-ui';
import StixCyberObservableCreation from './stix_cyber_observables/StixCyberObservableCreation';
import StixCyberObservablesRightBar from './stix_cyber_observables/StixCyberObservablesRightBar';
import Security from '../../../utils/Security';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListLines from '../../../components/list_lines/ListLines';
import StixCyberObservablesLines, {
  stixCyberObservablesLinesQuery,
  stixCyberObservablesLinesSearchQuery,
} from './stix_cyber_observables/StixCyberObservablesLines';
import ToolBar from '../data/ToolBar';
import { Theme } from '../../../components/Theme';
import {
  StixCyberObservablesLinesPaginationQuery$data,
} from './stix_cyber_observables/__generated__/StixCyberObservablesLinesPaginationQuery.graphql';
import { QueryRenderer } from '../../../relay/environment';
import useCopy from '../../../utils/hooks/useCopy';
import {
  StixCyberObservablesLinesSearchQuery$data,
} from './stix_cyber_observables/__generated__/StixCyberObservablesLinesSearchQuery.graphql';
import useAuth from '../../../utils/hooks/useAuth';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import {
  StixCyberObservableLine_node$data,
} from './stix_cyber_observables/__generated__/StixCyberObservableLine_node.graphql';
import { filtersWithEntityType, initialFilterGroup } from '../../../utils/filters/filtersUtils';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    paddingRight: 250,
  },
}));

const LOCAL_STORAGE_KEY = 'view-stixCyberObservables';

const StixCyberObservables: FunctionComponent = () => {
  const classes = useStyles();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      filters: initialFilterGroup,
      searchTerm: '',
      sortBy: 'created_at',
      orderAsc: false,
      openExports: false,
      types: [] as string[],
    },
  );
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
  } = useEntityToggle<StixCyberObservableLine_node$data>(LOCAL_STORAGE_KEY);

  const handleToggle = (type: string) => {
    if (types?.includes(type)) {
      helpers.handleAddProperty(
        'types',
        types.filter((x) => x !== type),
      );
    } else {
      helpers.handleAddProperty('types', types ? [...types, type] : [type]);
    }
  };

  const handleClear = () => {
    helpers.handleAddProperty('types', []);
  };

  const getValuesForCopy = (
    data: StixCyberObservablesLinesSearchQuery$data,
  ) => {
    return (data.stixCyberObservables?.edges ?? []).map((o) => (o
      ? { id: o.node.id, value: o.node.observable_value }
      : { id: '', value: '' }));
  };

  const handleCopy = useCopy<StixCyberObservablesLinesSearchQuery$data>(
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
      query: stixCyberObservablesLinesSearchQuery,
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
        width: '12%',
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
        width: '15%',
        isSortable: false,
      },
      created_at: {
        label: 'Date',
        width: '10%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        width: '10%',
        isSortable: isRuntimeSort,
      },
    };
  };

  const renderLines = () => {
    const finalType = (types && types.length > 0) ? types : 'Stix-Cyber-Observable';
    const toolBarFilters = filtersWithEntityType(filters, finalType);
    return (
      <>
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
          handleToggleExports={helpers.handleToggleExports}
          openExports={openExports}
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          exportEntityType="Stix-Cyber-Observable"
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
          <QueryRenderer
            query={stixCyberObservablesLinesQuery}
            variables={paginationOptions}
            render={({
              props,
            }: {
              props: StixCyberObservablesLinesPaginationQuery$data;
            }) => (
              <StixCyberObservablesLines
                data={props}
                paginationOptions={paginationOptions}
                dataColumns={buildColumns()}
                initialLoading={props === null}
                onLabelClick={helpers.handleAddFilter}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
                setNumberOfElements={helpers.handleSetNumberOfElements}
              />
            )}
          />
        </ListLines>
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
      </>
    );
  };

  return (
    <ExportContextProvider>
      <div className={classes.container}>
        {renderLines()}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCyberObservableCreation
            paginationKey="Pagination_stixCyberObservables"
            paginationOptions={paginationOptions}
            contextual={false}
            open={false}
            handleClose={undefined}
            type={undefined}
            display={undefined}
            speeddial={false}
            inputValue={undefined}
          />
        </Security>
        <StixCyberObservablesRightBar
          types={types}
          handleToggle={handleToggle}
          handleClear={handleClear}
        />
      </div>
    </ExportContextProvider>
  );
};

export default StixCyberObservables;
