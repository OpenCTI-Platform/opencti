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
import { isUniqFilter } from '../common/lists/Filters';
import { UserContext } from '../../../utils/Security';

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
        label: 'Relationship type',
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
      created_at: {
        label: 'Creation date',
        width: '10%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '15%',
        isSortable: isRuntimeSort,
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
      numberOfElements,
      openExports,
    } = this.state;
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
              openExports={openExports}
              exportEntityType="stix_core_relationship"
              disableCards={true}
              keyword={searchTerm}
              filters={filters}
              paginationOptions={paginationOptions}
              numberOfElements={numberOfElements}
              availableFilterKeys={[
                'fromId',
                'toId',
                'fromTypes',
                'toTypes',
                'markedBy',
                'created_start_date',
                'created_end_date',
                'createdBy',
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
                    setNumberOfElements={this.setNumberOfElements.bind(this)}
                  />
                )}
              />
            </ListLines>
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
      <div>{view === 'lines' ? this.renderLines(paginationOptions) : ''}</div>
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
