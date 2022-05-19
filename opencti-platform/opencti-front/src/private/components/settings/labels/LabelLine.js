import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert } from '@mui/icons-material';
import { LabelOutline } from 'mdi-material-ui';
import { compose } from 'ramda';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import LabelPopover from './LabelPopover';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'default',
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 5,
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

class LabelLineComponent extends Component {
  render() {
    const { fd, classes, node, dataColumns, paginationOptions } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true} button={true}>
        <ListItemIcon style={{ color: node.color }}>
          <LabelOutline />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.value.width }}
              >
                {node.value}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.color.width }}
              >
                {node.color}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                {fd(node.created_at)}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <LabelPopover
            labelId={node.id}
            paginationOptions={paginationOptions}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

LabelLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const LabelLineFragment = createFragmentContainer(LabelLineComponent, {
  node: graphql`
    fragment LabelLine_node on Label {
      id
      value
      color
      created_at
    }
  `,
});

export const LabelLine = compose(
  inject18n,
  withStyles(styles),
)(LabelLineFragment);

class LabelLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.color.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={140}
                  height="100%"
                />
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

LabelLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const LabelLineDummy = compose(
  inject18n,
  withStyles(styles),
)(LabelLineDummyComponent);
