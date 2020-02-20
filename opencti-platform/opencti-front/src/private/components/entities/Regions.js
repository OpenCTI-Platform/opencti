import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import RegionsLines, { regionsLinesQuery } from './regions/RegionsLines';
import RegionCreation from './regions/RegionCreation';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';

class Regions extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'Regions-view',
    );
    this.state = {
      sortBy: propOr('name', 'sortBy', params),
      orderAsc: propOr(true, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'Regions-view',
      this.state,
    );
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

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  renderLines(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      openExports,
      numberOfElements,
    } = this.state;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '60%',
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
        handleToggleExports={this.handleToggleExports.bind(this)}
        openExports={openExports}
        exportEntityType="Region"
        keyword={searchTerm}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
      >
        <QueryRenderer
          query={regionsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <RegionsLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              setNumberOfElements={this.setNumberOfElements.bind(this)}
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
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <RegionCreation paginationOptions={paginationOptions} />
        </Security>
      </div>
    );
  }
}

Regions.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(inject18n, withRouter)(Regions);
