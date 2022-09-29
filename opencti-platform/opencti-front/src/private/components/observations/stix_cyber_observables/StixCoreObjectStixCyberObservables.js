import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter, append } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import * as R from 'ramda';
import { withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import { UserContext } from '../../../../utils/Security';
import StixCoreObjectStixCyberObservablesLines, {
  stixCoreObjectStixCyberObservablesLinesQuery,
} from './StixCoreObjectStixCyberObservablesLines';
import StixCyberObservablesRightBar from './StixCyberObservablesRightBar';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import { isUniqFilter } from '../../common/lists/Filters';
import StixCoreObjectStixCyberObservablesEntities, {
  stixCoreObjectStixCyberObservablesEntitiesQuery,
} from './StixCoreObjectStixCyberObservablesEntities';
import ToolBar from '../../data/ToolBar';

const styles = () => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
});

class StixCoreObjectStixCyberObservables extends Component {
  constructor(props) {
    super(props);
    let params = {};
    if (!props.noState) {
      params = buildViewParamsFromUrlAndStorage(
        props.history,
        props.location,
        `view-observables-${props.entityId}`,
      );
    }
    this.state = {
      sortBy: R.propOr('created_at', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
      openToType: false,
      toType: 'All',
      targetStixCyberObservableTypes: ['Stix-Cyber-Observable'],
      numberOfElements: { number: 0, symbol: '' },
      openEntityType: false,
      openRelationshipType: false,
      openExports: false,
      selectedElements: null,
      deSelectedElements: null,
      selectAll: false,
    };
  }

  saveView() {
    if (!this.props.noState) {
      saveViewParameters(
        this.props.history,
        this.props.location,
        `view-observables-${this.props.entityId}`,
        this.state,
      );
    }
  }

  handleChangeView(mode) {
    this.setState({ view: mode }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
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

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports });
  }

  handleToggle(type) {
    if (this.state.targetStixCyberObservableTypes.includes(type)) {
      this.setState({
        targetStixCyberObservableTypes:
          filter((t) => t !== type, this.state.targetStixCyberObservableTypes)
            .length === 0
            ? ['Stix-Cyber-Observable']
            : filter(
              (t) => t !== type,
              this.state.targetStixCyberObservableTypes,
            ),
      });
    } else {
      this.setState({
        targetStixCyberObservableTypes: append(
          type,
          filter(
            (t) => t !== 'Stix-Cyber-Observable',
            this.state.targetStixCyberObservableTypes,
          ),
        ),
      });
    }
  }

  handleClear() {
    this.setState({ targetStixCyberObservableTypes: [] }, () => this.saveView());
  }

  handleToggleSelectEntity(entity, event) {
    event.stopPropagation();
    event.preventDefault();
    const { selectedElements, deSelectedElements, selectAll } = this.state;
    if (entity.id in (selectedElements || {})) {
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

  // eslint-disable-next-line class-methods-use-this
  buildColumnsLines() {
    return {
      relationship_type: {
        label: 'Relationship type',
        width: '15%',
        isSortable: true,
      },
      observable_value: {
        label: 'Value',
        width: '25%',
        isSortable: false,
      },
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: false,
      },
      start_time: {
        label: 'First obs.',
        width: '15%',
        isSortable: true,
      },
      stop_time: {
        label: 'Last obs.',
        width: '15%',
        isSortable: true,
      },
      confidence: {
        label: 'Confidence level',
        isSortable: true,
      },
    };
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc, numberOfElements, filters, openExports, view } = this.state;
    const {
      stixCoreObjectLink,
      isRelationReversed,
      disableExport,
      stixCoreObjectId,
    } = this.props;
    let exportFilters = paginationOptions.filters;
    exportFilters = R.append(
      { key: 'fromId', values: [stixCoreObjectId] },
      exportFilters,
    );
    const exportPaginationOptions = {
      ...paginationOptions,
      filters: exportFilters,
    };
    let availableFilterKeys = [
      'relationship_type',
      'markedBy',
      'createdBy',
      'created_start_date',
      'created_end_date',
    ];
    if (isRelationReversed) {
      availableFilterKeys = R.prepend('toTypes', availableFilterKeys);
    } else {
      availableFilterKeys = R.prepend('fromTypes', availableFilterKeys);
    }
    return (
      <UserContext.Consumer>
        {() => (
          <ListLines
            sortBy={sortBy}
            orderAsc={orderAsc}
            dataColumns={this.buildColumnsLines()}
            handleSort={this.handleSort.bind(this)}
            handleAddFilter={this.handleAddFilter.bind(this)}
            handleRemoveFilter={this.handleRemoveFilter.bind(this)}
            handleChangeView={this.handleChangeView.bind(this)}
            displayImport={true}
            handleToggleExports={
              disableExport ? null : this.handleToggleExports.bind(this)
            }
            paginationOptions={exportPaginationOptions}
            openExports={openExports}
            exportEntityType="stix-core-relationship"
            secondaryAction={true}
            filters={filters}
            availableFilterKeys={availableFilterKeys}
            availableEntityTypes={['Stix-Cyber-Observable']}
            numberOfElements={numberOfElements}
            noPadding={true}
            disableCards={true}
            enableEntitiesView={true}
            currentView={view}
          >
            <QueryRenderer
              query={stixCoreObjectStixCyberObservablesLinesQuery}
              variables={{ count: 25, ...paginationOptions }}
              render={({ props }) => (
                <StixCoreObjectStixCyberObservablesLines
                  data={props}
                  paginationOptions={paginationOptions}
                  stixCoreObjectLink={stixCoreObjectLink}
                  dataColumns={this.buildColumnsLines()}
                  initialLoading={props === null}
                  setNumberOfElements={this.setNumberOfElements.bind(this)}
                  isRelationReversed={isRelationReversed}
                />
              )}
            />
          </ListLines>
        )}
      </UserContext.Consumer>
    );
  }

  // eslint-disable-next-line class-methods-use-this
  buildColumnsEntities(helper) {
    const isRuntimeSort = helper.isRuntimeFieldEnable();
    return {
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      observable_value: {
        label: 'Value',
        width: '30%',
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '20%',
        isSortable: false,
      },
      created_at: {
        label: 'Creation date',
        width: '18%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
      },
    };
  }

  renderEntities(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      numberOfElements,
      filters,
      openExports,
      selectAll,
      selectedElements,
      deSelectedElements,
      view,
      searchTerm,
    } = this.state;
    const {
      stixCoreObjectLink,
      isRelationReversed,
      disableExport,
      stixCoreObjectId,
    } = this.props;
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original
        - Object.keys(deSelectedElements || {}).length;
    }
    let finalFilters = filters;
    finalFilters = R.assoc(
      'relatedTo',
      [{ id: stixCoreObjectId, value: stixCoreObjectId }],
      finalFilters,
    );
    return (
      <UserContext.Consumer>
        {({ helper }) => (
          <div>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={this.buildColumnsEntities(helper)}
              handleSort={this.handleSort.bind(this)}
              handleSearch={this.handleSearch.bind(this)}
              handleAddFilter={this.handleAddFilter.bind(this)}
              handleRemoveFilter={this.handleRemoveFilter.bind(this)}
              handleChangeView={this.handleChangeView.bind(this)}
              onToggleEntity={this.handleToggleSelectEntity.bind(this)}
              handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
              paginationOptions={paginationOptions}
              selectAll={selectAll}
              displayImport={true}
              handleToggleExports={
                disableExport ? null : this.handleToggleExports.bind(this)
              }
              openExports={openExports}
              exportEntityType="Stix-Cyber-Observable"
              iconExtension={true}
              filters={filters}
              availableFilterKeys={[
                'entity_type',
                'markedBy',
                'createdBy',
                'created_start_date',
                'created_end_date',
              ]}
              availableEntityTypes={['Stix-Cyber-Observable']}
              numberOfElements={numberOfElements}
              noPadding={true}
              disableCards={true}
              enableEntitiesView={true}
              currentView={view}
            >
              <QueryRenderer
                query={stixCoreObjectStixCyberObservablesEntitiesQuery}
                variables={{ count: 25, ...paginationOptions }}
                render={({ props }) => (
                  <StixCoreObjectStixCyberObservablesEntities
                    data={props}
                    paginationOptions={paginationOptions}
                    stixCoreObjectLink={stixCoreObjectLink}
                    dataColumns={this.buildColumnsEntities(helper)}
                    onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                    initialLoading={props === null}
                    setNumberOfElements={this.setNumberOfElements.bind(this)}
                    isRelationReversed={isRelationReversed}
                    onLabelClick={this.handleAddFilter.bind(this)}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
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
              withSmallPaddingRight={true}
            />
          </div>
        )}
      </UserContext.Consumer>
    );
  }

  render() {
    const {
      classes,
      stixCoreObjectId,
      relationshipType,
      noRightBar,
      isRelationReversed,
      defaultStartTime,
      defaultStopTime,
    } = this.props;
    const {
      view,
      targetStixCyberObservableTypes,
      sortBy,
      orderAsc,
      filters,
      searchTerm,
    } = this.state;
    let finalFilters = convertFilters(
      R.pipe(R.dissoc('fromTypes'), R.dissoc('toTypes'))(filters),
    );
    let paginationOptions = {
      fromTypes: filters.fromTypes
        ? R.pluck('id', filters.fromTypes)
        : targetStixCyberObservableTypes,
      search: searchTerm,
      toId: stixCoreObjectId,
      relationship_type: relationshipType || 'stix-core-relationship',
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
    };
    if (isRelationReversed) {
      paginationOptions = {
        toTypes: filters.toTypes
          ? R.pluck('id', filters.toTypes)
          : targetStixCyberObservableTypes,
        search: searchTerm,
        fromId: stixCoreObjectId,
        relationship_type: relationshipType || 'stix-core-relationship',
        orderBy: sortBy,
        orderMode: orderAsc ? 'asc' : 'desc',
        filters: finalFilters,
      };
    } else if (view === 'entities') {
      finalFilters = R.append(
        { key: 'relatedTo', values: [stixCoreObjectId] },
        finalFilters,
      );
      paginationOptions = {
        search: searchTerm,
        orderBy: sortBy,
        orderMode: orderAsc ? 'asc' : 'desc',
        filters: finalFilters,
      };
    }
    return (
      <div className={classes.container}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        {view === 'entities' ? this.renderEntities(paginationOptions) : ''}
        <StixCoreRelationshipCreationFromEntity
          entityId={stixCoreObjectId}
          targetStixCyberObservableTypes={['Stix-Cyber-Observable']}
          isRelationReversed={!isRelationReversed}
          allowedRelationshipTypes={
            relationshipType ? [relationshipType] : null
          }
          paddingRight={220}
          paginationOptions={paginationOptions}
          defaultStartTime={defaultStartTime}
          defaultStopTime={defaultStopTime}
          connectionKey={
            view === 'entities' ? 'Pagination_stixCyberObservables' : null
          }
        />
        {!noRightBar && (
          <StixCyberObservablesRightBar
            types={targetStixCyberObservableTypes}
            handleToggle={this.handleToggle.bind(this)}
            handleClear={this.handleClear.bind(this)}
          />
        )}
      </div>
    );
  }
}

StixCoreObjectStixCyberObservables.propTypes = {
  stixCoreObjectId: PropTypes.string,
  noRightBar: PropTypes.bool,
  relationshipType: PropTypes.string,
  stixCoreObjectLink: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  isRelationReversed: PropTypes.bool,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixCoreObjectStixCyberObservables);
