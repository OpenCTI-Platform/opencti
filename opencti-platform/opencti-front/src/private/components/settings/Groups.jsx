import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../relay/environment';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import GroupsLines, { groupsLinesQuery } from './groups/GroupsLines';
import GroupCreation from './groups/GroupCreation';
import AccessesMenu from './AccessesMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';
import withRouter from '../../../utils/compat_router/withRouter';

export const groupsSearchQuery = graphql`
  query GroupsSearchQuery($search: String) {
    groups(search: $search) {
      edges {
        node {
          id
          name
          description
          created_at
          updated_at
          roles {
            edges {
              node {
                id
                name
              }
            }
          }
          group_confidence_level {
            max_confidence
          }
        }
      }
    }
  }
`;

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
});

const LOCAL_STORAGE_KEY = 'groups';
class Groups extends Component {
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
      default_assignation: {
        label: 'Default membership',
        width: '12%',
        isSortable: true,
      },
      auto_new_marking: {
        label: 'Auto new markings',
        width: '12%',
        isSortable: true,
      },
      no_creators: {
        label: 'No creators',
        width: '12%',
        isSortable: true,
      },
      group_confidence_level: {
        label: 'Max Confidence',
        width: '12%',
        isSortable: true,
      },
      created_at: {
        label: 'Platform creation date',
        width: '15%',
        isSortable: true,
      },
      updated_at: {
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
        displayImport={false}
        secondaryAction={false}
        keyword={searchTerm}
      >
        <QueryRenderer
          query={groupsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <GroupsLines
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
    const { t, classes } = this.props;
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container} data-testid="groups-settings-page">
        <Breadcrumbs elements={[{ label: t('Settings') }, { label: t('Security') }, { label: t('Groups'), current: true }]} />
        <AccessesMenu />
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <GroupCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

Groups.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
  navigate: PropTypes.func,
  location: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(Groups);
