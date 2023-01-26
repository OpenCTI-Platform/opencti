import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import RelationshipsStixCoreRelationshipsLines, {
  relationshipsStixCoreRelationshipsLinesQuery,
} from './relationships/RelationshipsStixCoreRelationshipsLines';
import inject18n from '../../../components/i18n';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import { isUniqFilter } from '../../../utils/filters/filtersUtils';
import { UserContext } from '../../../utils/hooks/useAuth';
import ToolBar from './ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';

class Relationships extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-stix-core-relationships',
    );
    this.state = {
      sortBy: R.propOr('created_at', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
      numberOfElements: { number: 0, symbol: '' },
      selectedElements: null,
      deSelectedElements: null,
      selectAll: false,
      openExports: false,
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-stix-core-relationships',
      this.state,
    );
  }

  handleChangeView(mode) {
    this.setState({ view: mode }, () => this.saveView());
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports });
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

  handleToggleSelectEntity(entity, _, forceRemove = []) {
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

  // eslint-disable-next-line class-methods-use-this
  buildColumns(helper) {
    const isRuntimeSort = helper.isRuntimeFieldEnable();
    return {
      fromType: {
        label: 'From type',
        width: '10%',
        isSortable: false,
      },
      fromName: {
        label: 'From name',
        width: '18%',
        isSortable: false,
      },
      relationship_type: {
        label: 'Type',
        width: '10%',
        isSortable: true,
      },
      toType: {
        label: 'To type',
        width: '10%',
        isSortable: false,
      },
      toName: {
        label: 'To name',
        width: '18%',
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        width: '7%',
        isSortable: isRuntimeSort,
      },
      creator: {
        label: 'Creator',
        width: '7%',
        isSortable: true,
      },
      created_at: {
        label: 'Creation date',
        width: '10%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
        width: '8%',
      },
    };
  }

  renderLines(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      numberOfElements,
      openExports,
      selectedElements,
      deSelectedElements,
      selectAll,
    } = this.state;
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original
        - Object.keys(deSelectedElements || {}).length;
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
              handleChangeView={this.handleChangeView.bind(this)}
              handleToggleExports={this.handleToggleExports.bind(this)}
              handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
              openExports={openExports}
              selectAll={selectAll}
              exportEntityType="stix-core-relationship"
              disableCards={true}
              secondaryAction={true}
              iconExtension={true}
              noPadding={true}
              keyword={searchTerm}
              filters={filters}
              paginationOptions={paginationOptions}
              numberOfElements={numberOfElements}
              availableFilterKeys={[
                'relationship_type',
                'fromId',
                'toId',
                'fromTypes',
                'toTypes',
                'markedBy',
                'created_start_date',
                'created_end_date',
                'createdBy',
                'creator',
              ]}
            >
              <QueryRenderer
                query={relationshipsStixCoreRelationshipsLinesQuery}
                variables={{ count: 25, ...paginationOptions }}
                render={({ props }) => (
                  <RelationshipsStixCoreRelationshipsLines
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
              filters={R.assoc(
                'entity_type',
                [
                  {
                    id: 'stix-core-relationship',
                    value: 'stix-core-relationship',
                  },
                ],
                filters,
              )}
              search={searchTerm}
              handleClearSelectedElements={this.handleClearSelectedElements.bind(
                this,
              )}
            />
          </div>
        )}
      </UserContext.Consumer>
    );
  }

  render() {
    const { view, sortBy, orderAsc, searchTerm, filters } = this.state;
    let finalFilters = convertFilters(filters);
    const fromId = R.head(finalFilters.filter((n) => n.key === 'fromId'))?.values || null;
    const toId = R.head(finalFilters.filter((n) => n.key === 'toId'))?.values || null;
    const fromTypes = R.head(finalFilters.filter((n) => n.key === 'fromTypes'))?.values || null;
    const toTypes = R.head(finalFilters.filter((n) => n.key === 'toTypes'))?.values || null;
    finalFilters = finalFilters.filter(
      (n) => !['fromId', 'toId', 'fromTypes', 'toTypes'].includes(n.key),
    );
    const paginationOptions = {
      fromId,
      toId,
      fromTypes,
      toTypes,
      search: searchTerm,
      filters: finalFilters,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <ExportContextProvider>
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
      </div>
      </ExportContextProvider>
    );
  }
}

Relationships.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(Relationships);
