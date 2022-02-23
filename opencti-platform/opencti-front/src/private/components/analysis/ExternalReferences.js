import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import ExternalReferencesLines, {
  externalReferencesLinesQuery,
} from './external_references/ExternalReferencesLines';
import ExternalReferenceCreation from './external_references/ExternalReferenceCreation';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';

export const externalReferencesSearchQuery = graphql`
  query ExternalReferencesSearchQuery(
    $search: String
    $filters: [ExternalReferencesFiltering]
  ) {
    externalReferences(search: $search, filters: $filters) {
      edges {
        node {
          id
          source_name
          external_id
          description
          url
        }
      }
    }
  }
`;

class ExternalReferences extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-external_references',
    );
    this.state = {
      sortBy: propOr('created', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-external_references',
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc, searchTerm } = this.state;
    const dataColumns = {
      source_name: {
        label: 'Source name',
        width: '15%',
        isSortable: true,
      },
      external_id: {
        label: 'External ID',
        width: '10%',
        isSortable: true,
      },
      url: {
        label: 'URL',
        width: '50%',
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
        displayImport={true}
        secondaryAction={true}
        keyword={searchTerm}
      >
        <QueryRenderer
          query={externalReferencesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <ExternalReferencesLines
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
    const { view, sortBy, orderAsc, searchTerm } = this.state;
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ExternalReferenceCreation paginationOptions={paginationOptions} />
        </Security>
      </div>
    );
  }
}

ExternalReferences.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(inject18n, withRouter)(ExternalReferences);
