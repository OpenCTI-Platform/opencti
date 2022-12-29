import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withRouter } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import UsersLines, { usersLinesQuery } from './users/UsersLines';
import UserCreation from './users/UserCreation';
import AccessesMenu from './AccessesMenu';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
});

class Users extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'Users-view',
    );
    this.state = {
      sortBy: propOr('name', 'sortBy', params),
      orderAsc: propOr(true, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'Users-view',
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
        width: '20%',
        isSortable: true,
      },
      user_email: {
        label: 'Email',
        width: '30%',
        isSortable: true,
      },
      firstname: {
        label: 'Firstname',
        width: '15%',
        isSortable: true,
      },
      lastname: {
        label: 'Lastname',
        width: '15%',
        isSortable: true,
      },
      otp: {
        label: '2FA',
        width: '5%',
        isSortable: false,
      },
      created_at: {
        label: 'Creation date',
        width: '10%',
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
        secondaryAction={false}
        keyword={searchTerm}
      >
        <QueryRenderer
          query={usersLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <UsersLines
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
    const { classes } = this.props;
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        <AccessesMenu />
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <UserCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

Users.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(Users);
