import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  assoc, compose, dissoc, propOr,
} from 'ramda';
import { withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import AttackPatternsLines, {
  attackPatternsLinesQuery,
} from './attack_patterns/AttackPatternsLines';
import AttackPatternCreation from './attack_patterns/AttackPatternCreation';

class AttackPatterns extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'AttackPatterns-view',
    );
    this.state = {
      sortBy: propOr('name', 'sortBy', params),
      orderAsc: propOr(true, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      filters: {},
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'AttackPatterns-view',
      dissoc('filters', this.state),
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleAddFilter(key, value, event) {
    event.stopPropagation();
    event.preventDefault();
    this.setState({ filters: assoc(key, [value], this.state.filters) });
  }

  handleRemoveFilter(key) {
    this.setState({ filters: dissoc(key, this.state.filters) });
  }

  renderLines(paginationOptions) {
    const {
      sortBy, orderAsc, searchTerm, filters,
    } = this.state;
    const dataColumns = {
      killChainPhases: {
        label: 'Kill chain phases',
        width: '20%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '20%',
        isSortable: true,
      },
      tags: {
        label: 'Tags',
        width: '20%',
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
        handleRemoveFilter={this.handleRemoveFilter.bind(this)}
        displayImport={true}
        keyword={searchTerm}
        filters={filters}
      >
        <QueryRenderer
          query={attackPatternsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <AttackPatternsLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              onTagClick={this.handleAddFilter.bind(this)}
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
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters,
    };
    return (
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <AttackPatternCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

AttackPatterns.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
)(AttackPatterns);
