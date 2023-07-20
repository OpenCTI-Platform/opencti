import React from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  convertFilters,
} from '../../../../utils/ListParameters';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ExportContextProvider from '../../../../utils/ExportContextProvider';

const StixDomainObjectIndicators = ({
  stixDomainObjectId,
  stixDomainObjectLink,
  defaultStartTime,
  defaultStopTime,
}) => {
/*  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-indicators-${props.stixDomainObjectId}`,
    );
    state = {
      sortBy: R.propOr('created_at', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
      indicatorTypes: [],
      observableTypes: [],
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
      selectedElements: null,
      deSelectedElements: null,
      selectAll: false,
    };
  } */

  /*
  saveView() {
    saveViewParameters(
      props.history,
      props.location,
      `view-indicators-${props.stixDomainObjectId}`,
      state,
    );
  }

  handleSearch(value) {
    setState({ searchTerm: value }, () => saveView());
  }

  handleSort(field, orderAsc) {
    setState({ sortBy: field, orderAsc }, () => saveView());
  }

  handleToggleExports() {
    setState({ openExports: !state.openExports }, () => {
      if (typeof props.onChangeOpenExports === 'function') {
        props.onChangeOpenExports(state.openExports);
      }
    });
  }

  handleToggleSelectEntity(entity, event, forceRemove = []) {
    event.stopPropagation();
    event.preventDefault();
    const { selectedElements, deSelectedElements, selectAll } = state;
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
      setState({
        selectAll: false,
        selectedElements: newSelectedElements,
        deSelectedElements: null,
      });
    } else if (entity.id in (selectedElements || {})) {
      const newSelectedElements = R.omit([entity.id], selectedElements);
      setState({
        selectAll: false,
        selectedElements: newSelectedElements,
      });
    } else if (selectAll && entity.id in (deSelectedElements || {})) {
      const newDeSelectedElements = R.omit([entity.id], deSelectedElements);
      setState({
        deSelectedElements: newDeSelectedElements,
      });
    } else if (selectAll) {
      const newDeSelectedElements = R.assoc(
        entity.id,
        entity,
        deSelectedElements || {},
      );
      setState({
        deSelectedElements: newDeSelectedElements,
      });
    } else {
      const newSelectedElements = R.assoc(
        entity.id,
        entity,
        selectedElements || {},
      );
      setState({
        selectAll: false,
        selectedElements: newSelectedElements,
      });
    }
  }

  handleToggleSelectAll() {
    setState({
      selectAll: !state.selectAll,
      selectedElements: null,
      deSelectedElements: null,
    });
  }

  handleClearSelectedElements() {
    setState({
      selectAll: false,
      selectedElements: null,
      deSelectedElements: null,
    });
  }

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (state.filters[key] && state.filters[key].length > 0) {
      setState(
        {
          filters: R.assoc(
            key,
            isUniqFilter(key)
              ? [{ id, value }]
              : R.uniqBy(R.prop('id'), [
                { id, value },
                ...state.filters[key],
              ]),
            state.filters,
          ),
        },
        () => saveView(),
      );
    } else {
      setState(
        {
          filters: R.assoc(key, [{ id, value }], state.filters),
        },
        () => saveView(),
      );
    }
  }

  handleRemoveFilter(key) {
    setState({ filters: R.dissoc(key, state.filters) }, () => saveView());
  }

  setNumberOfElements(numberOfElements) {
    setState({ numberOfElements });
  }
*/

  // eslint-disable-next-line class-methods-use-this
  /*  buildColumns(platformModuleHelpers) {
    const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
    return {
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
  } */

  /* renderLines(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      openExports,
      numberOfElements,
      selectedElements,
      deSelectedElements,
      selectAll,
      filters,
      indicatorTypes,
      observableTypes,
    } = state;
    /!*    const { stixDomainObjectId, stixDomainObjectLink } = props;
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original
        - Object.keys(deSelectedElements || {}).length;
    } *!/
    /!* let finalFilters = filters;
    finalFilters = {
      ...finalFilters,
      indicates: [{ id: stixDomainObjectId, value: stixDomainObjectId }],
    };
    if (indicatorTypes.length) {
      finalFilters = {
        ...finalFilters,
        pattern_type: indicatorTypes.map((n) => ({ id: n, value: n })),
      };
    }
    if (observableTypes.length) {
      finalFilters = {
        ...finalFilters,
        x_opencti_main_observable_type: observableTypes.map((n) => ({
          id: n,
          value: n,
        })),
      };
    } *!/
    /!*   return (
      <UserContext.Consumer>
        {({ platformModuleHelpers }) => (
          <div>
            <ListLines
              sortBy={sortBy}//
              orderAsc={orderAsc}//
              dataColumns={buildColumns(platformModuleHelpers)}//
              handleSort={handleSort.bind(this)}//
              handleSearch={handleSearch.bind(this)}//
              handleAddFilter={handleAddFilter.bind(this)}//
              handleRemoveFilter={handleRemoveFilter.bind(this)}//
              handleToggleExports={handleToggleExports.bind(this)}//
              openExports={openExports}//
              handleToggleSelectAll={handleToggleSelectAll.bind(this)}//
              selectAll={selectAll}//
              noPadding={typeof props.onChangeOpenExports === 'function'}//
              paginationOptions={paginationOptions}
              exportEntityType="Indicator"//
              filters={filters}//
              exportContext={`of-entity-${stixDomainObjectId}`}
              keyword={searchTerm}//
              secondaryAction={true}//
              iconExtension={true}//
              numberOfElements={numberOfElements}//
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
                'pattern_type',
                'x_opencti_main_observable_type',
              ]}
            >
              <QueryRenderer
                query={stixDomainObjectIndicatorsLinesQuery}
                variables={{ count: 25, ...paginationOptions }}
                render={({ props }) => (
                  <StixDomainObjectIndicatorsLines
                    data={props}
                    paginationOptions={paginationOptions}
                    entityLink={stixDomainObjectLink}
                    entityId={stixDomainObjectId}
                    dataColumns={buildColumns(platformModuleHelpers)}
                    initialLoading={props === null}
                    setNumberOfElements={setNumberOfElements.bind(this)}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    onToggleEntity={handleToggleSelectEntity.bind(this)}
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
              filters={finalFilters}
              search={searchTerm}
              handleClearSelectedElements={handleClearSelectedElements.bind(this)}
              variant="large"
            />
          </div>
        )}
      </UserContext.Consumer>
    ); *!/
  } */

  //const { stixDomainObjectId, defaultStartTime, defaultStopTime } = props;
  const {
    view,
    sortBy,
    orderAsc,
    searchTerm,
    filters,
    indicatorTypes,
    observableTypes,
    openExports,
  } = state;
  let finalFilters = convertFilters(filters);
  finalFilters = R.append(
    { key: 'indicates', values: [stixDomainObjectId] },
    finalFilters,
  );
  if (indicatorTypes.length > 0) {
    finalFilters = R.append(
      { key: 'pattern_type', values: indicatorTypes },
      finalFilters,
    );
  }
  if (observableTypes.length > 0) {
    finalFilters = R.append(
      {
        key: 'x_opencti_main_observable_type',
        operator: 'match',
        values: observableTypes.map((type) => type.toLowerCase().replace(/\*/g, '')),
      },
      finalFilters,
    );
  }
  const paginationOptions = {
    search: searchTerm,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
    filters: finalFilters,
  };
  return (
      <ExportContextProvider>
        <div style={{ marginTop: 20 }}>
          {view === 'lines'
          ?? <StixDomainObjectIndicatorsEntitiesView
              stixDomainObjectId={stixDomainObjectId}
              stixDomainObjectLink={stixDomainObjectLink}
              localStorage={localStorage}
              observableTypes={observableTypes}
              indicatorTypes={indicatorTypes}
              handleChangeView={handleChangeView}
              currentView={currentView}
              disableExport={disableExport}
            />}
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
        </div>
      </ExportContextProvider>
  );
};

StixDomainObjectIndicators.propTypes = {
  stixDomainObjectId: PropTypes.string,
  stixDomainObjectLink: PropTypes.string,
  onChangeOpenExports: PropTypes.func,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export default StixDomainObjectIndicators;
