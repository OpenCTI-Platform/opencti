import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { QueryRenderer } from '../../../relay/environment';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import RolesLines, { rolesLinesQuery } from './roles/RolesLines';
import AccessesMenu from './AccessesMenu';
import RoleCreation from './roles/RoleCreation';
import withRouter from '../../../utils/compat_router/withRouter';
import Breadcrumbs from '../../../components/Breadcrumbs';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
});

const LOCAL_STORAGE_KEY = 'roles';

class Roles extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.navigate,
      props.location,
      LOCAL_STORAGE_KEY,
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
      this.props.navigate,
      this.props.location,
      LOCAL_STORAGE_KEY,
      this.state,
    );
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc, searchTerm } = this.state;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '40%',
        isSortable: true,
      },
      groups: {
        label: 'Groups with this role',
        width: '20%',
        isSortable: false,
      },
      created_at: {
        label: 'Platform creation date',
        width: '20%',
        isSortable: true,
      },
      updated_at: {
        label: 'Modification date',
        width: '20%',
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
          query={rolesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <RolesLines
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
    const { classes, t } = this.props;
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container} data-testid='roles-settings-page'>
        <Breadcrumbs elements={[{ label: t('Settings') }, { label: t('Security') }, { label: t('Roles'), current: true }]} />
        <AccessesMenu />
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <RoleCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

Roles.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
  navigate: PropTypes.func,
  location: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(Roles);
