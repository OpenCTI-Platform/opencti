import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import StixDomainObjectIndicatorsLines, {
  stixDomainObjectIndicatorsLinesQuery,
} from './StixDomainObjectIndicatorsLines';
import ListLines from '../../../../components/list_lines/ListLines';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import IndicatorsRightBar from './IndicatorsRightBar';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ToolBar from '../../data/ToolBar';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import ExportContextProvider from '../../../../utils/ExportContextProvider';

class StixDomainObjectIndicators extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-indicators-${props.stixDomainObjectId}`,
    );
    this.state = {
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
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-indicators-${this.props.stixDomainObjectId}`,
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports }, () => {
      if (typeof this.props.onChangeOpenExports === 'function') {
        this.props.onChangeOpenExports(this.state.openExports);
      }
    });
  }

  handleToggleIndicatorType(type) {
    if (this.state.indicatorTypes.includes(type)) {
      this.setState({
        indicatorTypes: R.filter((t) => t !== type, this.state.indicatorTypes),
      });
    } else {
      this.setState({
        indicatorTypes: R.append(type, this.state.indicatorTypes),
      });
    }
  }

  handleToggleObservableType(type) {
    if (this.state.observableTypes.includes(type)) {
      this.setState({
        observableTypes: R.filter(
          (t) => t !== type,
          this.state.observableTypes,
        ),
      });
    } else {
      this.setState({
        observableTypes: R.append(type, this.state.observableTypes),
      });
    }
  }

  handleClearObservableTypes() {
    this.setState({ observableTypes: [] }, () => this.saveView());
  }

  handleToggleSelectEntity(entity, event, forceRemove = []) {
    event.stopPropagation();
    event.preventDefault();
    const { selectedElements, deSelectedElements, selectAll } = this.state;
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
      this.setState({
        selectAll: false,
        selectedElements: newSelectedElements,
        deSelectedElements: null,
      });
    } else if (entity.id in (selectedElements || {})) {
      const newSelectedElements = R.omit([entity.id], selectedElements);
      this.setState({
        selectAll: false,
        selectedElements: newSelectedElements,
      });
    } else if (selectAll && entity.id in (deSelectedElements || {})) {
      const newDeSelectedElements = R.omit([entity.id], deSelectedElements);
      this.setState({
        deSelectedElements: newDeSelectedElements,
      });
    } else if (selectAll) {
      const newDeSelectedElements = R.assoc(
        entity.id,
        entity,
        deSelectedElements || {},
      );
      this.setState({
        deSelectedElements: newDeSelectedElements,
      });
    } else {
      const newSelectedElements = R.assoc(
        entity.id,
        entity,
        selectedElements || {},
      );
      this.setState({
        selectAll: false,
        selectedElements: newSelectedElements,
      });
    }
  }

  handleToggleSelectAll() {
    this.setState({
      selectAll: !this.state.selectAll,
      selectedElements: null,
      deSelectedElements: null,
    });
  }

  handleClearSelectedElements() {
    this.setState({
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
    if (this.state.filters[key] && this.state.filters[key].length > 0) {
      this.setState(
        {
          filters: R.assoc(
            key,
            isUniqFilter(key)
              ? [{ id, value }]
              : R.uniqBy(R.prop('id'), [
                { id, value },
                ...this.state.filters[key],
              ]),
            this.state.filters,
          ),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          filters: R.assoc(key, [{ id, value }], this.state.filters),
        },
        () => this.saveView(),
      );
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) }, () => this.saveView());
  }

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  // eslint-disable-next-line class-methods-use-this
  buildColumns(helper) {
    const isRuntimeSort = helper.isRuntimeFieldEnable();
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
  }

  renderLines(paginationOptions) {
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
    } = this.state;
    const { stixDomainObjectId, stixDomainObjectLink } = this.props;
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original
        - Object.keys(deSelectedElements || {}).length;
    }
    let finalFilters = filters;
    finalFilters = R.assoc(
      'indicates',
      [{ id: stixDomainObjectId, value: stixDomainObjectId }],
      finalFilters,
    );
    if (indicatorTypes.length) {
      finalFilters = R.assoc(
        'pattern_type',
        R.map((n) => ({ id: n, value: n }), indicatorTypes),
        finalFilters,
      );
    }
    if (observableTypes.length) {
      finalFilters = R.assoc(
        'x_opencti_main_observable_type',
        R.map((n) => ({ id: n, value: n }), observableTypes),
        finalFilters,
      );
    }
    return (
      <UserContext.Consumer>
        {({ helper }) => (
          <div>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={this.buildColumns(helper)}
              handleSort={this.handleSort.bind(this)}
              handleSearch={this.handleSearch.bind(this)}
              handleAddFilter={this.handleAddFilter.bind(this)}
              handleRemoveFilter={this.handleRemoveFilter.bind(this)}
              handleToggleExports={this.handleToggleExports.bind(this)}
              openExports={openExports}
              handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
              selectAll={selectAll}
              noPadding={typeof this.props.onChangeOpenExports === 'function'}
              paginationOptions={paginationOptions}
              exportEntityType="Indicator"
              filters={filters}
              exportContext={`of-entity-${stixDomainObjectId}`}
              keyword={searchTerm}
              secondaryAction={true}
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
                'x_opencti_detection',
                'sightedBy',
                'basedOn',
                'revoked',
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
                    dataColumns={this.buildColumns(helper)}
                    initialLoading={props === null}
                    setNumberOfElements={this.setNumberOfElements.bind(this)}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    onToggleEntity={this.handleToggleSelectEntity.bind(this)}
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
              handleClearSelectedElements={this.handleClearSelectedElements.bind(
                this,
              )}
              variant="large"
            />
          </div>
        )}
      </UserContext.Consumer>
    );
  }

  render() {
    const { stixDomainObjectId, defaultStartTime, defaultStopTime } = this.props;
    const {
      view,
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      indicatorTypes,
      observableTypes,
      openExports,
    } = this.state;
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
          values: R.map(
            (type) => type.toLowerCase().replace(/\*/g, ''),
            observableTypes,
          ),
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
      <div style={{ marginTop: 20, paddingRight: 250 }}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
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
          handleToggleIndicatorType={this.handleToggleIndicatorType.bind(this)}
          handleToggleObservableType={this.handleToggleObservableType.bind(
            this,
          )}
          handleClearObservableTypes={this.handleClearObservableTypes.bind(
            this,
          )}
          openExports={openExports}
        />
      </div>
      </ExportContextProvider>
    );
  }
}

StixDomainObjectIndicators.propTypes = {
  stixDomainObjectId: PropTypes.string,
  stixDomainObjectLink: PropTypes.string,
  history: PropTypes.object,
  onChangeOpenExports: PropTypes.func,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export default StixDomainObjectIndicators;
