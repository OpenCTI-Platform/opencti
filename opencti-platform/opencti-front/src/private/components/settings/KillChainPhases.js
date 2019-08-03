import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import KillChainPhasesLines, { killChainPhasesLinesQuery } from './kill_chain_phases/KillChainPhasesLines';
import KillChainPhaseCreation from './kill_chain_phases/KillChainPhaseCreation';

export const killChainPhasesSearchQuery = graphql`
  query KillChainPhasesSearchQuery($search: String) {
    killChainPhases(search: $search) {
      edges {
        node {
          id
          kill_chain_name
          phase_name
        }
      }
    }
  }
`;

class KillChainPhases extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'phase_order',
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
      kill_chain_name: {
        label: 'Kill chain name',
        width: '30%',
        isSortable: true,
      },
      phase_name: {
        label: 'Phase name',
        width: '35%',
        isSortable: true,
      },
      phase_order: {
        label: 'Order',
        width: '10%',
        isSortable: true,
      },
      created: {
        label: 'Creation date',
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
        displayImport={false}
        secondaryAction={true}
      >
        <QueryRenderer
          query={killChainPhasesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <KillChainPhasesLines
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
        <KillChainPhaseCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

KillChainPhases.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n)(KillChainPhases);
