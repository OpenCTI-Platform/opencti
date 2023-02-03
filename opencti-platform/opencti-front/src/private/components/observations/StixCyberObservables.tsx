import { FunctionComponent, useState } from 'react';
import * as R from 'ramda';
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
import { StixCyberObservableLine_node$data } from './stix_cyber_observables/__generated__/StixCyberObservableLine_node.graphql';
import { Filters } from '../../../components/list_lines';
import { ModuleHelper } from '../../../utils/platformModulesHelper';
import {
  StixCyberObservablesLinesPaginationQuery$data,
} from './stix_cyber_observables/__generated__/StixCyberObservablesLinesPaginationQuery.graphql';
import { QueryRenderer } from '../../../relay/environment';
import useCopy from '../../../utils/hooks/useCopy';
import { StixCyberObservablesLinesSearchQuery$data } from './stix_cyber_observables/__generated__/StixCyberObservablesLinesSearchQuery.graphql';
import { UserContext } from '../../../utils/hooks/useAuth';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import ExportContextProvider from '../../../utils/ExportContextProvider';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    paddingRight: 250,
  },
}));

const LOCAL_STORAGE_KEY = 'view-stix-cyber-observables';

const StixCyberObservables: FunctionComponent = () => {
  const classes = useStyles();

  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      filters: {} as Filters,
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

  const [selectedElements, setSelectedElements] = useState<Record<string, StixCyberObservableLine_node$data>>({});
  const [deSelectedElements, setDeSelectedElements] = useState<Record<string, StixCyberObservableLine_node$data>>({});

  const [selectAll, setSelectAll] = useState<boolean>(false);

  const handleToggle = (type: string) => {
    if (types?.includes(type)) {
      helpers.handleAddProperty('types', types.filter((x) => x !== type));
    } else {
      helpers.handleAddProperty('types', types ? [...types, type] : [type]);
    }
  };

  const handleClear = () => {
    helpers.handleAddProperty('types', []);
  };

  const handleToggleSelectEntity = (
    entity:
    | StixCyberObservableLine_node$data
    | StixCyberObservableLine_node$data[],
    event: React.SyntheticEvent,
    forceRemove: StixCyberObservableLine_node$data[],
  ) => {
    event.stopPropagation();
    event.preventDefault();
    if (Array.isArray(entity)) {
      const currentIds = R.values(selectedElements).map((n) => n.id);
      const givenIds = entity.map((n) => n.id);
      const addedIds = givenIds.filter((n) => !currentIds.includes(n));
      let newSelectedElements = {
        ...selectedElements,
        ...R.indexBy(
          R.prop('id'),
          entity.filter((n) => addedIds.includes(n.id)),
        ),
      };
      if (forceRemove.length > 0) {
        newSelectedElements = R.omit(
          forceRemove.map((n) => n.id),
          newSelectedElements,
        );
      }
      setSelectAll(false);
      setSelectedElements(newSelectedElements);
      setDeSelectedElements({});
    } else if (entity.id in (selectedElements || {})) {
      const newSelectedElements = R.omit([entity.id], selectedElements);
      setSelectAll(false);
      setSelectedElements(newSelectedElements);
    } else if (selectAll && entity.id in (deSelectedElements || {})) {
      const newDeSelectedElements = R.omit([entity.id], deSelectedElements);
      setDeSelectedElements(newDeSelectedElements);
    } else if (selectAll) {
      const newDeSelectedElements = {
        ...deSelectedElements,
        [entity.id]: entity,
      };
      setDeSelectedElements(newDeSelectedElements);
    } else {
      const newSelectedElements = {
        ...selectedElements,
        [entity.id]: entity,
      };
      setSelectAll(false);
      setSelectedElements(newSelectedElements);
    }
  };

  const handleToggleSelectAll = () => {
    setSelectAll(!selectAll);
    setSelectedElements({});
    setDeSelectedElements({});
  };

  const handleClearSelectedElements = () => {
    setSelectAll(false);
    setSelectedElements({});
    setDeSelectedElements({});
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
        ...filters,
        entity_type: types ? types.map((n) => ({ id: n, value: n })) : [],
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

  const buildColumns = (helper: ModuleHelper | undefined) => {
    const isRuntimeSort = helper?.isRuntimeFieldEnable();
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
        label: 'Creator',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '15%',
        isSortable: false,
      },
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
        width: '8%',
      },
    };
  };

  const renderLines = () => {
    let finalType;
    if (types && types.length > 0) {
      finalType = types.map((n) => ({ id: n, value: n }));
    } else {
      finalType = [{ id: 'Stix-Cyber-Observable', value: 'Stix-Cyber-Observable' }];
    }
    const finalFilters = { ...viewStorage.filters, entity_type: finalType };
    let numberOfSelectedElements = Object.keys(selectedElements).length;
    if (selectAll) {
      numberOfSelectedElements = (numberOfElements?.original ?? 0)
        - Object.keys(deSelectedElements).length;
    }
    return (
      <UserContext.Consumer>
        {({ helper }) => (
          <div>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={buildColumns(helper)}
              handleSort={helpers.handleSort}
              handleSearch={helpers.handleSearch}
              handleAddFilter={helpers.handleAddFilter}
              handleRemoveFilter={helpers.handleRemoveFilter}
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
                'labelledBy',
                'markedBy',
                'created_at_start_date',
                'created_at_end_date',
                'x_opencti_score',
                'createdBy',
                'sightedBy',
                'creator',
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
                    dataColumns={buildColumns(helper)}
                    initialLoading={props === null}
                    onLabelClick={helpers.handleAddFilter}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    onToggleEntity={handleToggleSelectEntity}
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
              filters={finalFilters}
              search={searchTerm}
              handleClearSelectedElements={handleClearSelectedElements}
              variant="large"
              handleCopy={handleCopy}
            />
          </div>
        )}
      </UserContext.Consumer>
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
          openExports={openExports}
          contextual={false}
          open={false}
          handleClose={undefined}
          type={undefined}
          display={undefined}
          speeddial={false}
        />
      </Security>
      <StixCyberObservablesRightBar
        types={types}
        handleToggle={handleToggle}
        handleClear={handleClear}
        openExports={openExports}
      />
    </div>
    </ExportContextProvider>
  );
};

export default StixCyberObservables;
