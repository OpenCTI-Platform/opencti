import React, { FunctionComponent, useState } from 'react';
import * as R from 'ramda';
import {
  StixDomainObjectIndicatorsLinesQuery$data, StixDomainObjectIndicatorsLinesQuery$variables,
} from '@components/observations/indicators/__generated__/StixDomainObjectIndicatorsLinesQuery.graphql';
import StixDomainObjectIndicatorsLines, {
  stixDomainObjectIndicatorsLinesQuery,
} from './StixDomainObjectIndicatorsLines';
import ListLines from '../../../../components/list_lines/ListLines';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipCreationFromEntity
  from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import IndicatorsRightBar from './IndicatorsRightBar';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';
import ToolBar from '../../data/ToolBar';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';

interface StixDomainObjectIndicatorsProps {
  stixDomainObjectId: string,
  stixDomainObjectLink: string,
  defaultStartTime: string,
  defaultStopTime: string,
  onChangeOpenExports: () => void,
}
const StixDomainObjectIndicators: FunctionComponent<StixDomainObjectIndicatorsProps> = ({
  stixDomainObjectId,
  stixDomainObjectLink,
  defaultStartTime,
  defaultStopTime,
  onChangeOpenExports,
}) => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const LOCAL_STORAGE_KEY = `view-indicators-${stixDomainObjectId}`;

  const [indicatorTypes, setIndicatorTypes] = useState<string[]>([]);
  const [observableTypes, setObservablesTypes] = useState<string[]>([]);
  const additionnalFilters = [];
  additionnalFilters.push(
    { key: 'indicates', values: [stixDomainObjectId] },
  );
  if (indicatorTypes.length > 0) {
    additionnalFilters.push({ key: 'pattern_type', values: indicatorTypes });
  }
  if (observableTypes.length > 0) {
    additionnalFilters.push({
      key: 'x_opencti_main_observable_type',
      operator: 'match',
      values: observableTypes.map((type) => type.toLowerCase().replace(/\*/g, '')),
    });
  }
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<StixDomainObjectIndicatorsLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: {},
      searchTerm: '',
      sortBy: 'created_at',
      orderAsc: false,
      openExports: false,
      view: 'lines',
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
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
    numberOfSelectedElements,
  } = useEntityToggle(LOCAL_STORAGE_KEY);

  const handleToggleIndicatorType = (type: string) => {
    if (indicatorTypes.includes(type)) {
      setIndicatorTypes(indicatorTypes.filter((t) => t !== type));
    } else {
      setIndicatorTypes(R.append(type, indicatorTypes));
    }
  };

  const handleToggleObservableType = (type: string) => {
    if (observableTypes.includes(type)) {
      setObservablesTypes(observableTypes.filter((t) => t !== type));
    } else {
      setObservablesTypes(R.append(type, observableTypes));
    }
  };

  const handleClearObservableTypes = () => {
    setObservablesTypes([]);
  };
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns = {
    pattern_type: {
      label: 'Type',
      width: '10%',
      isSortable: true,
    },
    name: {
      label: 'Name',
      width: '30%',
      isSortable: true,
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
    valid_until: {
      label: 'Valid until',
      width: '15%',
      isSortable: true,
    },
    objectMarking: {
      label: 'Marking',
      isSortable: isRuntimeSort,
    },
  };

  const renderLines = () => {
    return (
          <div>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={dataColumns}
              handleSort={helpers.handleSort}
              handleSearch={helpers.handleSearch}
              handleAddFilter={helpers.handleAddFilter}
              handleRemoveFilter={helpers.handleRemoveFilter}
              handleToggleExports={helpers.handleToggleExports}
              openExports={openExports}
              handleToggleSelectAll={handleToggleSelectAll}
              selectAll={selectAll}
              noPadding={typeof onChangeOpenExports === 'function'}
              paginationOptions={paginationOptions}
              exportEntityType="Indicator"
              filters={filters}
              exportContext={`of-entity-${stixDomainObjectId}`}
              keyword={searchTerm}
              iconExtension={true}
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
                'objectContains',
                'sightedBy',
                'x_opencti_detection',
                'basedOn',
                'revoked',
                'creator',
                'confidence',
                'indicator_types',
              ]}
            >
              <QueryRenderer
                query={stixDomainObjectIndicatorsLinesQuery}
                variables={paginationOptions}
                render={({ props }: { props: StixDomainObjectIndicatorsLinesQuery$data }) => (
                  <StixDomainObjectIndicatorsLines
                    data={props}
                    paginationOptions={paginationOptions}
                    entityLink={stixDomainObjectLink}
                    entityId={stixDomainObjectId}
                    dataColumns={dataColumns}
                    initialLoading={props === null}
                    setNumberOfElements={helpers.handleSetNumberOfElements}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    onToggleEntity={onToggleEntity}
                    selectAll={selectAll}
                  />
                )}
              />
            </ListLines>
            <ToolBar
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              numberOfSelectedElements={numberOfSelectedElements}
              selectAll={selectAll}
              filters={filters}
              search={searchTerm}
              handleClearSelectedElements={handleClearSelectedElements}
              variant="large"
            />
          </div>
    );
  };
  return (
    <ExportContextProvider>
      <div style={{ marginTop: 20, paddingRight: 250 }}>
        {renderLines()}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            entityId={stixDomainObjectId}
            isRelationReversed={true}
            targetStixDomainObjectTypes={['Indicator']}
            paginationOptions={paginationOptions}
            openExports={openExports}
            paddingRight={270}
            connectionKey="Pagination_indicators"
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
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
  );
};

export default StixDomainObjectIndicators;
