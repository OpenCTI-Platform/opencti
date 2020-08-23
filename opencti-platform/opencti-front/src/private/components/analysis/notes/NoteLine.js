import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Avatar from '@material-ui/core/Avatar';
import { MoreVertOutlined } from '@material-ui/icons';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import inject18n from '../../../../components/i18n';
import NotePopover from './NotePopover';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'default',
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
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
    right: -10,
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

class NoteLineComponent extends Component {
  render() {
    const {
      fd, classes, dataColumns, node, paginationOptions,
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/analysis/notes/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Avatar classes={{ root: classes.avatar }}>
            {node.source_name.substring(0, 1)}
          </Avatar>
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.source_name.width }}
              >
                {node.source_name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.external_id.width }}
              >
                {node.external_id}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.url.width }}
              >
                {node.url}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                {fd(node.created)}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <NotePopover
            noteId={node.id}
            paginationOptions={paginationOptions}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

NoteLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const NoteLineFragment = createFragmentContainer(
  NoteLineComponent,
  {
    node: graphql`
      fragment NoteLine_node on Note {
        id
        attribute_abstract
        content
        created
      }
    `,
  },
);

export const NoteLine = compose(
  inject18n,
  withStyles(styles),
)(NoteLineFragment);

class NoteLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Avatar classes={{ root: classes.avatarDisabled }}>A</Avatar>
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.source_name.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.external_id.width }}
              >
                <div className="fakeItem" style={{ width: '70%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.url.width }}
              >
                <div className="fakeItem" style={{ width: '60%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <MoreVertOutlined />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

NoteLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const NoteLineDummy = compose(
  inject18n,
  withStyles(styles),
)(NoteLineDummyComponent);
