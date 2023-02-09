import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import { QueryRenderer } from '../../../relay/environment';
import { buildViewParamsFromUrlAndStorage, convertFilters, saveViewParameters } from '../../../utils/ListParameters';
import ListLines from '../../../components/list_lines/ListLines';
import ObservedDatasLines, { observedDatasLinesQuery } from './observed_data/ObservedDatasLines';
import inject18n from '../../../components/i18n';
import ObservedDataCreation from './observed_data/ObservedDataCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import { isUniqFilter } from '../../../utils/filters/filtersUtils';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';

class ObservedDatas extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-observed_data${props.objectId ? `-${props.objectId}` : ''}`,
    );
    this.state = {
      sortBy: R.propOr('created', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
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
      `view-observed_data${
        this.props.objectId ? `-${this.props.objectId}` : ''
      }`,
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
  }

  renderLines(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
      selectedElements,
      deSelectedElements,
      selectAll,
    } = this.state;
    const { objectId, authorId } = this.props;
    let exportContext = null;
    if (objectId) {
      exportContext = `of-entity-${objectId}`;
    } else if (authorId) {
      exportContext = `of-entity-${authorId}`;
    }
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original
        - Object.keys(deSelectedElements || {}).length;
    }
    let toolBarFilters = filters;
    toolBarFilters = {
      ...toolBarFilters,
      entity_type: [{ id: 'Observed-Data', value: 'Observed-Data' }],
    };
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
            exportEntityType="Observed-Data"
            exportContext={exportContext}
            keyword={searchTerm}
            filters={filters}
            paginationOptions={paginationOptions}
            numberOfElements={numberOfElements}
            iconExtension={true}
            availableFilterKeys={[
              'labelledBy',
              'createdBy',
              'markedBy',
              'created_start_date',
              'created_end_date',
              'confidence',
            ]}
          >
            <QueryRenderer
              query={observedDatasLinesQuery}
              variables={{ count: 25, ...paginationOptions }}
              render={({ props }) => (
                <ObservedDatasLines
                  data={props}
                  paginationOptions={paginationOptions}
                  dataColumns={this.buildColumns(helper)}
                  initialLoading={props === null}
                  onLabelClick={this.handleAddFilter.bind(this)}
                  selectedElements={selectedElements}
                  deSelectedElements={deSelectedElements}
                  onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                  selectAll={selectAll}
                  setNumberOfElements={this.setNumberOfElements.bind(this)}
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
          handleClearSelectedElements={this.handleClearSelectedElements.bind(this)}
          type="Observed-Data"
          />
          </div>
        )}
      </UserContext.Consumer>
    );
  }

  render() {
    const {
      match: {
        params: { observedDataType },
      },
      objectId,
      authorId,
    } = this.props;
    const { view, sortBy, orderAsc, searchTerm, filters } = this.state;
    const observedDataFilterClass = observedDataType !== 'all' && observedDataType !== undefined
      ? observedDataType.replace(/_/g, ' ')
      : '';
    const finalFilters = convertFilters(filters);
    if (observedDataFilterClass) {
      finalFilters.push({
        key: 'observedData_types',
        values: [observedDataFilterClass],
      });
    }
    if (authorId) finalFilters.push({ key: 'createdBy', values: [authorId] });
    if (objectId) finalFilters.push({ key: 'objectContains', values: [objectId] });
    const paginationOptions = {
      filters: finalFilters,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <ExportContextProvider>
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ObservedDataCreation paginationOptions={paginationOptions} />
        </Security>
      </div>
      </ExportContextProvider>
    );
  }
}

ObservedDatas.propTypes = {
  objectId: PropTypes.string,
  authorId: PropTypes.string,
  t: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
  onChangeOpenExports: PropTypes.func,
};

export default R.compose(inject18n, withRouter)(ObservedDatas);
