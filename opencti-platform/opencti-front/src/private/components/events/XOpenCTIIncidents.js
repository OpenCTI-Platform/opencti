import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  assoc, compose, dissoc, propOr,
} from 'ramda';
import { withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListCards from '../../../components/list_cards/ListCards';
import ListLines from '../../../components/list_lines/ListLines';
import XOpenCTIIncidentsCards, {
  XOpenCTIIncidentsCardsQuery,
} from './x_opencti_incidents/XOpenCTIIncidentsCards';
import XOpenCTIIncidentsLines, {
  XOpenCTIIncidentsLinesQuery,
} from './x_opencti_incidents/XOpenCTIIncidentsLines';
import XOpenCTIIncidentCreation from './x_opencti_incidents/XOpenCTIIncidentCreation';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';

class XOpenCTIXOpenCTIIncidents extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-x_opencti_incident',
    );
    this.state = {
      sortBy: propOr('created', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      filters: {},
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-x_opencti_incident',
      dissoc('filters', this.state),
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
    this.setState({
      filters: assoc(key, [{ id, value }], this.state.filters),
    });
  }

  handleRemoveFilter(key) {
    this.setState({ filters: dissoc(key, this.state.filters) });
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
        exportEntityType="X-OpenCTI-Incident"
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
          query={XOpenCTIIncidentsCardsQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <XOpenCTIIncidentsCards
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

  renderLines(paginationOptions) {
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
        width: '35%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '25%',
        isSortable: false,
      },
      created: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        width: '15%',
        isSortable: true,
      },
    };
    return (
      <ListLines
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
        exportEntityType="XOpenCTIXOpenCTIIncident"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'labels',
          'markingDefinitions',
          'created_start_date',
          'created_end_date',
          'createdBy',
        ]}
      >
        <QueryRenderer
          query={XOpenCTIIncidentsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <XOpenCTIIncidentsLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              onLabelClick={this.handleAddFilter.bind(this)}
              setNumberOfElements={this.setNumberOfElements.bind(this)}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const {
      view, sortBy, orderAsc, searchTerm, filters,
    } = this.state;
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
          <XOpenCTIIncidentCreation paginationOptions={paginationOptions} />
        </Security>
      </div>
    );
  }
}

XOpenCTIXOpenCTIIncidents.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(inject18n, withRouter)(XOpenCTIXOpenCTIIncidents);
