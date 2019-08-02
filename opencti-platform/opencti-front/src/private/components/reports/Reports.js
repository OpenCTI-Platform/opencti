/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import ReportsLines, { reportsLinesQuery } from './ReportsLines';
import inject18n from '../../../components/i18n';
import ReportCreation from './ReportCreation';

const styles = () => ({
  header: {
    margin: '0 0 10px 0',
  },
  linesContainer: {
    marginTop: 0,
    paddingTop: 0,
  },
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  inputLabel: {
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
});

class Reports extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'published',
      orderAsc: false,
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
        {displayCreate === true ? <ReportCreation paginationOptions={paginationOptions} /> : ''}
      </div>
    );
  }
}

Reports.propTypes = {
  objectId: PropTypes.string,
  authorId: PropTypes.string,
  classes: PropTypes.object,
  match: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  displayCreate: PropTypes.bool,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(Reports);
