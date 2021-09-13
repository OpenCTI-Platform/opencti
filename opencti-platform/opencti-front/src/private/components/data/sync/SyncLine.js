import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { MoreVert } from '@material-ui/icons';
import { DatabaseImportOutline } from 'mdi-material-ui';
import { compose } from 'ramda';
import Slide from '@material-ui/core/Slide';
import Skeleton from '@material-ui/lab/Skeleton';
import SyncPopover from './SyncPopover';
import inject18n from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
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
  filter: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    marginRight: 7,
    borderRadius: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.chip,
    height: 20,
    marginRight: 10,
  },
});

class SyncLineLineComponent extends Component {
  render() {
    const {
      classes, node, dataColumns, paginationOptions, t, nsdt,
    } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <DatabaseImportOutline />
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
                style={{ width: dataColumns.uri.width }}
              >
                {node.uri}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.uri.width }}
              >
                <code>{node.stream_id}</code>
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.running.width }}
              >
                <ItemBoolean
                  variant="inList"
                  label={node.running ? t('Yes') : t('No')}
                  status={node.running}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.current_state.width }}
              >
                {nsdt(node.current_state)}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <SyncPopover
            syncId={node.id}
            paginationOptions={paginationOptions}
            running={node.running}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

SyncLineLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const SyncLineFragment = createFragmentContainer(SyncLineLineComponent, {
  node: graphql`
    fragment SyncLine_node on Synchronizer {
      id
      name
      uri
      stream_id
      running
      current_state
      ssl_verify
    }
  `,
});

export const SyncLine = compose(
  inject18n,
  withStyles(styles),
)(SyncLineFragment);

class SyncDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Skeleton animation="wave" variant="circle" width={30} height={30} />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.uri.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.stream_id.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.running.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.current_state.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
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

SyncDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const SyncLineDummy = compose(
  inject18n,
  withStyles(styles),
)(SyncDummyComponent);
