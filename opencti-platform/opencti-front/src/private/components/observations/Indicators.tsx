import React, { useState } from 'react';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import ListLines from '../../../components/list_lines/ListLines';
import IndicatorsLines, { indicatorsLinesQuery } from './indicators/IndicatorsLines';
import IndicatorCreation from './indicators/IndicatorCreation';
import IndicatorsRightBar from './indicators/IndicatorsRightBar';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { IndicatorLine_node$data } from './indicators/__generated__/IndicatorLine_node.graphql';
import {
  IndicatorsLinesPaginationQuery,
  IndicatorsLinesPaginationQuery$variables,
} from './indicators/__generated__/IndicatorsLinesPaginationQuery.graphql';
import { ModuleHelper } from '../../../utils/platformModulesHelper';
import { IndicatorLineDummyComponent } from './indicators/IndicatorLine';

const useStyles = makeStyles(() => ({
  container: {
    paddingRight: 250,
  },
}));

const LOCAL_STORAGE_KEY = 'view-indicators';

const Indicators = () => {
  const classes = useStyles();
  const [indicatorTypes, setIndicatorTypes] = useState<string[]>([]);
  const [observableTypes, setObservableTypes] = useState<string[]>([]);

  const additionnalFilters = [];
  if (indicatorTypes.length > 0) {
    additionnalFilters.push(
      {
        key: 'pattern_type',
        values: indicatorTypes,
        operator: 'eq',
        filterMode: 'or',
      },
    );
  }
  if (observableTypes.length > 0) {
    additionnalFilters.push(
      {
        key: 'x_opencti_main_observable_type',
        values: observableTypes,
        operator: 'eq',
        filterMode: 'or',
      },
    );
  }

  const { viewStorage, paginationOptions, helpers: storageHelpers } = usePaginationLocalStorage < IndicatorsLinesPaginationQuery$variables >(LOCAL_STORAGE_KEY, {
    numberOfElements: { number: 0, symbol: '', original: 0 },
    filters: {},
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
    count: 25,
  }, additionnalFilters);

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
  } = useEntityToggle < IndicatorLine_node$data >('view-indicators');

  const queryRef = useQueryLoading < IndicatorsLinesPaginationQuery >(
    indicatorsLinesQuery,
    paginationOptions,
  );

  const handleToggleIndicatorType = (type: string) => {
    if (indicatorTypes.includes(type)) {
      setIndicatorTypes(indicatorTypes.filter(
        (t) => t !== type,
      ));
    } else {
      setIndicatorTypes(R.append(type, indicatorTypes));
    }
  };

  const handleToggleObservableType = (type: string) => {
    if (observableTypes.includes(type)) {
      setObservableTypes(observableTypes.filter(
        (t) => t !== type,
      ));
    } else {
      setObservableTypes(R.append(type, observableTypes));
    }
  };

  const handleClearObservableTypes = () => {
    setObservableTypes([]);
  };

  const renderLines = (helper: ModuleHelper | undefined) => {
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = (numberOfElements?.original ?? 0)
        - Object.keys(deSelectedElements || {}).length;
    }
    let toolBarFilters = filters;
    toolBarFilters = {
      ...toolBarFilters,
      entity_type: [{ id: 'Indicator', value: 'Indicator' }],
    };
    const isRuntimeSort = helper?.isRuntimeFieldEnable();
    const dataColumns = {
      pattern_type: {
        label: 'Pattern type',
        width: '8%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '22%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeSort ?? false,
      },
      creator: {
        label: 'Creators',
        width: '12%',
        isSortable: isRuntimeSort ?? false,
      },
      objectLabel: {
        label: 'Labels',
        width: '15%',
        isSortable: false,
      },
      created: {
        label: 'Date',
        width: '10%',
        isSortable: true,
      },
      valid_until: {
        label: 'Valid until',
        width: '10%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        width: '10%',
        isSortable: isRuntimeSort ?? false,
      },
    };
    return (
          <div>
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
              exportEntityType="Indicator"
              exportContext={null}
              iconExtension={true}
              keyword={searchTerm}
              filters={filters}
              paginationOptions={paginationOptions}
              numberOfElements={numberOfElements}
              availableFilterKeys={[
                'labelledBy',
                'markedBy',
                'created_start_date',
                'created_end_date',
                'valid_from_start_date',
                'valid_until_end_date',
                'x_opencti_score',
                'createdBy',
                'sightedBy',
                'x_opencti_detection',
                'basedOn',
                'revoked',
                'creator',
                'confidence',
                'indicator_types',
              ]}
            >
              {queryRef && (
                <React.Suspense
                  fallback={
                    <>
                      {Array(20)
                        .fill(0)
                        .map((idx) => (
                          <IndicatorLineDummyComponent
                            key={idx}
                            dataColumns={dataColumns}
                          />
                        ))}
                    </>
                  }
                >
                  <IndicatorsLines
                    queryRef={queryRef}
                    paginationOptions={paginationOptions}
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
              filters={toolBarFilters}
              search={searchTerm}
              handleClearSelectedElements={handleClearSelectedElements}
              variant="large"
              type="Indicator"
            />
          </div>
    );
  };

  return (
    <UserContext.Consumer>
      {({ helper }) => (
        <ExportContextProvider>
          <div className={classes.container}>
            {renderLines(helper)}
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <IndicatorCreation
                paginationOptions={paginationOptions}
              />
            </Security>
            <IndicatorsRightBar
              indicatorTypes={indicatorTypes}
              observableTypes={observableTypes}
              handleToggleIndicatorType={handleToggleIndicatorType}
              handleToggleObservableType={handleToggleObservableType}
              handleClearObservableTypes={handleClearObservableTypes}
              openExports={openExports}
            />
          </div>
        </ExportContextProvider>
      )}
    </UserContext.Consumer>
  );
};

export default Indicators;
