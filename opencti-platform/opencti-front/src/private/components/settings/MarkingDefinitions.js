import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import MarkingDefinitionsLines, {
  markingDefinitionsLinesQuery,
} from './marking_definitions/MarkingDefinitionsLines';
import MarkingDefinitionCreation from './marking_definitions/MarkingDefinitionCreation';

export const markingDefinitionsSearchQuery = graphql`
  query MarkingDefinitionsSearchQuery($search: String) {
    markingDefinitions(search: $search) {
      edges {
        node {
          id
          definition_type
          definition
        }
      }
    }
  }
`;

class MarkingDefinitions extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'definition',
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
      definition_type: {
        label: 'Definition type',
        width: '25%',
        isSortable: true,
      },
      definition: {
        label: 'Definition',
        width: '25%',
        isSortable: true,
      },
      color: {
        label: 'Color',
        width: '15%',
        isSortable: true,
      },
      level: {
        label: 'Level',
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
          query={markingDefinitionsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <MarkingDefinitionsLines
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
        <MarkingDefinitionCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

MarkingDefinitions.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n)(MarkingDefinitions);
