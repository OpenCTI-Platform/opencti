import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../relay/environment';
import { getParams, saveParams } from '../../../utils/ListParameters';
import ListLines from '../../../components/list_lines/ListLines';
import ReportsLines, { reportsLinesQuery } from './ReportsLines';
import inject18n from '../../../components/i18n';
import ReportCreation from './ReportCreation';

class Reports extends Component {
  constructor(props) {
    super(props);
    const params = getParams(
      props.history,
      props.location,
      'Reports-view',
    );
    this.state = {
      sortBy: propOr('published', 'sortBy', params),
      orderAsc: propOr('false', 'orderAsc', params) === 'true',
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
    };
  }

  saveView() {
    saveParams(
      this.props.history,
      this.props.location,
      'Reports-view',
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
    const { sortBy, orderAsc } = this.state;
    const dataColumns = {
      name: {
        label: 'Title',
        width: '40%',
        isSortable: true,
      },
      createdByRef: {
        label: 'Author',
        width: '20%',
        isSortable: true,
      },
      published: {
        label: 'Publication date',
        width: '15%',
        isSortable: true,
      },
      object_status: {
        label: 'Status',
        width: '10%',
        isSortable: true,
      },
      marking: {
        label: 'Marking',
        width: '15%',
        isSortable: false,
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
          query={reportsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <ReportsLines
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
      displayCreate,
      match: {
        params: { reportClass },
      },
      objectId,
      authorId,
    } = this.props;
    const {
      view, sortBy, orderAsc, searchTerm,
    } = this.state;
    const paginationOptions = {
      objectId,
      authorId,
      reportClass:
        reportClass !== 'all' && reportClass !== undefined
          ? reportClass.replace('_', ' ')
          : '',
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        {displayCreate === true ? (
          <ReportCreation paginationOptions={paginationOptions} />
        ) : (
          ''
        )}
      </div>
    );
  }
}

Reports.propTypes = {
  objectId: PropTypes.string,
  authorId: PropTypes.string,
  t: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
  displayCreate: PropTypes.bool,
};

export default compose(
  inject18n,
  withRouter,
)(Reports);
