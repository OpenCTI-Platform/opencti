import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withRouter } from 'react-router-dom';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import TaxiiLines, { TaxiiLinesQuery } from './taxii/TaxiiLines';
import TaxiiCollectionCreation from './taxii/TaxiiCollectionCreation';
import SharingMenu from './SharingMenu';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
});

class Taxii extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'taxii-view',
    );
    this.state = {
      orderAsc: propOr(true, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'taxii-view',
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
      name: {
        label: 'Name',
        width: '15%',
        isSortable: true,
      },
      description: {
        label: 'Description',
        width: '20%',
        isSortable: true,
      },
      filters: {
        label: 'Filters',
        width: '60%',
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
        keyword={searchTerm}
      >
        <QueryRenderer
          query={TaxiiLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <TaxiiLines
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
    const { classes } = this.props;
    const { view, sortBy, orderAsc, searchTerm } = this.state;
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        <SharingMenu />
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <TaxiiCollectionCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

Taxii.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(
  inject18n,
  withTheme,
  withRouter,
  withStyles(styles),
)(Taxii);
