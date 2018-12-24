/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { QueryRenderer } from 'react-relay';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { ArrowDropDown, ArrowDropUp } from '@material-ui/icons';
import environment from '../../relay/environment';
import UsersLines, { usersLinesQuery } from './user/UsersLines';
import inject18n from '../../components/i18n';
import UserCreation from './user/UserCreation';

const styles = () => ({
  windowScrollerWrapper: {
    flex: '1 1 auto',
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

const inlineStyles = {
  iconSort: {
    position: 'absolute',
    margin: '-3px 0 0 5px',
    padding: 0,
    top: '0px',
  },
  username: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  email: {
    float: 'left',
    width: '30%',
    fontSize: 12,
    fontWeight: '700',
  },
  firstname: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  lastname: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  created_at: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

class Users extends Component {
  constructor(props) {
    super(props);
    this.state = { sortBy: 'username', orderAsc: true };
  }

  handleChangeView(mode) {
    this.setState({ view: mode });
  }

  handleChangeSortBy(event) {
    this.setState({ sortBy: event.target.value });
  }

  reverse() {
    this.setState({ orderAsc: !this.state.orderAsc });
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label) {
    const { t } = this.props;
    return (
      <div style={inlineStyles[field]} onClick={this.reverseBy.bind(this, field)}>
        <span>{t(label)}</span>
        {this.state.sortBy === field ? this.state.orderAsc ? <ArrowDropDown style={inlineStyles.iconSort}/> : <ArrowDropUp style={inlineStyles.iconSort}/> : ''}
      </div>
    );
  }

  render() {
    const { classes } = this.props;
    const paginationOptions = {
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem classes={{ default: classes.item }} divider={false} style={{ paddingTop: 0 }}>
            <ListItemIcon>
              <span style={{ padding: '0 8px 0 8px', fontWeight: 700, fontSize: 12 }}>#</span>
            </ListItemIcon>
            <ListItemText primary={
              <div>
                {this.SortHeader('username', 'Username')}
                {this.SortHeader('email', 'Email address')}
                {this.SortHeader('firstname', 'Firstname')}
                {this.SortHeader('lastname', 'Lastname')}
                {this.SortHeader('created_at', 'Creation date')}
              </div>
            }/>
          </ListItem>
          <QueryRenderer
            environment={environment}
            query={usersLinesQuery}
            variables={{ count: 25, orderBy: this.state.sortBy, orderMode: this.state.orderAsc ? 'asc' : 'desc' }}
            render={({ error, props }) => {
              if (error) { // Errors
                return <UsersLines data={null} dummy={true}/>;
              }
              if (props) { // Done
                return <UsersLines data={props} paginationOptions={paginationOptions}/>;
              }
              // Loading
              return <UsersLines data={null} dummy={true}/>;
            }}
          />
        </List>
        <UserCreation paginationOptions={paginationOptions}/>
      </div>
    );
  }
}

Users.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Users);
