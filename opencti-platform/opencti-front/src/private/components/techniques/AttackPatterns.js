import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import AttackPatternsLines, {
  attackPatternsLinesQuery,
} from './attack_patterns/AttackPatternsLines';
import AttackPatternCreation from './attack_patterns/AttackPatternCreation';

class AttackPatterns extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'name',
      orderAsc: true,
      searchTerm: '',
      view: 'lines',
    };
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const dataColumns = {
      killChainPhases: {
        label: 'Kill chain phases',
        width: '20%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '40%',
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
        displayImport={true}
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
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const {
      view, sortBy, orderAsc, searchTerm,
    } = this.state;
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
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
};

export default compose(inject18n)(AttackPatterns);
