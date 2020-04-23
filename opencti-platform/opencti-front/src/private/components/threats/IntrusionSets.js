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
import IntrusionSetsCards, {
  intrusionSetsCardsQuery,
} from './intrusion_sets/IntrusionSetsCards';
import IntrusionSetsLines, {
  intrusionSetsLinesQuery,
} from './intrusion_sets/IntrusionSetsLines';
import IntrusionSetCreation from './intrusion_sets/IntrusionSetCreation';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';

class IntrusionSets extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-intrusion_sets',
    );
    this.state = {
      sortBy: propOr('name', 'sortBy', params),
      orderAsc: propOr(true, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('cards', 'view', params),
      filters: {},
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-intrusion_sets',
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
      tags: {
        label: 'Tags',
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
        exportEntityType="Intrusion-Set"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'tags',
          'markingDefinitions',
          'created_start_date',
          'created_end_date',
          'createdBy',
        ]}
      >
        <QueryRenderer
          query={intrusionSetsCardsQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <IntrusionSetsCards
              data={props}
              paginationOptions={paginationOptions}
              initialLoading={props === null}
              onTagClick={this.handleAddFilter.bind(this)}
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
      tags: {
        label: 'Tags',
        width: '25%',
        isSortable: true,
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
        exportEntityType="Intrusion-Set"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'tags',
          'markingDefinitions',
          'created_start_date',
          'created_end_date',
          'createdBy',
        ]}
      >
        <QueryRenderer
          query={intrusionSetsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <IntrusionSetsLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              onTagClick={this.handleAddFilter.bind(this)}
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
          <IntrusionSetCreation paginationOptions={paginationOptions} />
        </Security>
      </div>
    );
  }
}

IntrusionSets.propTypes = {
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(inject18n, withRouter)(IntrusionSets);
