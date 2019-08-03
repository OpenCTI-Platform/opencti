import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { MoreVert, Person } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import PersonPopover from './PersonPopover';

const styles = theme => ({
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  goIcon: {
    position: 'absolute',
    right: 10,
    marginRight: 0,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class PersonLineComponent extends Component {
  render() {
    const {
      fd, classes, dataColumns, node, me, paginationOptions,
    } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Person />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                {fd(node.created)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.modified.width }}
              >
                {fd(node.modified)}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <PersonPopover
            personId={node.id}
            paginationOptions={paginationOptions}
            disabled={!includes('ROLE_ADMIN', propOr([], 'grant', me))}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

PersonLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const PersonLineFragment = createFragmentContainer(PersonLineComponent, {
  node: graphql`
    fragment PersonLine_node on User {
      id
      name
      created
      modified
    }
  `,
  me: graphql`
    fragment PersonLine_me on User {
      grant
    }
  `,
});

export const PersonLine = compose(
  inject18n,
  withStyles(styles),
)(PersonLineFragment);

class PersonLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Person />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                <div className="fakeItem" style={{ width: 80 }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.modified.width }}
              >
                <div className="fakeItem" style={{ width: 80 }} />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <MoreVert />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

PersonLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const PersonLineDummy = compose(
  inject18n,
  withStyles(styles),
)(PersonLineDummyComponent);
