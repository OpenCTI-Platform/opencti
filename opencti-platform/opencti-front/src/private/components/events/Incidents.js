import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListCards from '../../../components/list_cards/ListCards';
import ListLines from '../../../components/list_lines/ListLines';
import IncidentsCards, {
  incidentsCardsQuery,
} from './incidents/IncidentsCards';
import IncidentsLines, {
  incidentsLinesQuery,
} from './incidents/IncidentsLines';
import IncidentCreation from './incidents/IncidentCreation';
import Security, {
  KNOWLEDGE_KNUPDATE,
  UserContext,
} from '../../../utils/Security';
import { isUniqFilter } from '../common/lists/Filters';

class Incidents extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-incidents',
    );
    this.state = {
      sortBy: R.propOr('created', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-incidents',
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

  renderCards(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = this.state;
    const dataColumns = {
      name: {
        label: 'Name',
      },
      created: {
        label: 'Creation date',
      },
      modified: {
        label: 'Modification date',
      },
    };
    return (
      <ListCards
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        handleSearch={this.handleSearch.bind(this)}
        handleChangeView={this.handleChangeView.bind(this)}
        handleAddFilter={this.handleAddFilter.bind(this)}
        handleRemoveFilter={this.handleRemoveFilter.bind(this)}
        handleToggleExports={this.handleToggleExports.bind(this)}
        openExports={openExports}
        exportEntityType="Incident"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'labelledBy',
          'markedBy',
          'created_start_date',
          'created_end_date',
          'createdBy',
        ]}
      >
        <QueryRenderer
          query={incidentsCardsQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <IncidentsCards
              data={props}
              paginationOptions={paginationOptions}
              initialLoading={props === null}
              onLabelClick={this.handleAddFilter.bind(this)}
              setNumberOfElements={this.setNumberOfElements.bind(this)}
            />
          )}
        />
      </ListCards>
    );
  }

  // eslint-disable-next-line class-methods-use-this
  buildColumns(helper) {
    const isRuntimeSort = helper.isRuntimeFieldEnable();
    return {
      name: {
        label: 'Name',
        width: '28%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '20%',
        isSortable: false,
      },
      created: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        width: '13%',
        isSortable: true,
      },
      x_opencti_workflow_id: {
        label: 'Status',
        width: '10%',
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
      filters,
      openExports,
      numberOfElements,
    } = this.state;
    return (
      <UserContext.Consumer>
        {({ helper }) => (
          <ListLines
            sortBy={sortBy}
            orderAsc={orderAsc}
            dataColumns={this.buildColumns(helper)}
            handleSort={this.handleSort.bind(this)}
            handleSearch={this.handleSearch.bind(this)}
            handleChangeView={this.handleChangeView.bind(this)}
            handleAddFilter={this.handleAddFilter.bind(this)}
            handleRemoveFilter={this.handleRemoveFilter.bind(this)}
            handleToggleExports={this.handleToggleExports.bind(this)}
            openExports={openExports}
            exportEntityType="Incident"
            keyword={searchTerm}
            filters={filters}
            paginationOptions={paginationOptions}
            numberOfElements={numberOfElements}
            availableFilterKeys={[
              'labelledBy',
              'markedBy',
              'x_opencti_workflow_id',
              'created_start_date',
              'created_end_date',
              'createdBy',
            ]}
          >
            <QueryRenderer
              query={incidentsLinesQuery}
              variables={{ count: 25, ...paginationOptions }}
              render={({ props }) => (
                <IncidentsLines
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
        )}
      </UserContext.Consumer>
    );
  }

  render() {
    const { view, sortBy, orderAsc, searchTerm, filters } = this.state;
    const finalFilters = convertFilters(filters);
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
    };
    return (
      <div>
        {view === 'cards' ? this.renderCards(paginationOptions) : ''}
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IncidentCreation paginationOptions={paginationOptions} />
        </Security>
      </div>
    );
  }
}

Incidents.propTypes = {
  history: PropTypes.object,
  location: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(Incidents);
